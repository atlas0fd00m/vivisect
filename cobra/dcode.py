"""

Cobra's distributed code module capable of allowing
serialization of code from one system to another.

Particularly useful for clustering and workunit stuff.

"""
import os
import imp
import sys
import logging
import importlib

import cobra

logger = logging.getLogger(__name__)


class DcodeServer:

    def getPythonModule(self, fullname, path=None):

        # Some serialization causes this to be a tuple
        # and find_module is SUPER SERIOUS about it being
        # a *list*... ;)
        if path is not None:
            path = list(path)

        fullname = fullname.split(".")[-1]

        try:
            fobj, filename, typeinfo = imp.find_module(fullname, path)
        except ImportError:
            return None

        if os.path.isdir(filename):
            typeinfo = ('.py', 'U', 1)
            filename = os.path.join(filename, "__init__.py")

        if not os.path.exists(filename):
            return None

        if typeinfo[0] != '.py':
            return None

        path = os.path.dirname(filename)
        with open(filename, 'rU') as f:
            fbytes = f.read()
        return (fbytes, filename, path)


class DcodeLoader(object):
    """
    This object gets returned by the DcodeFinder
    """
    def __init__(self, fbytes, filename, path):
        object.__init__(self)
        self.fbytes = fbytes
        self.filename = filename
        self.path = path

    def get_source(self, name):
        return self.fbytes

    def load_module(self, fullname):
        mod = sys.modules.get(fullname)
        if mod is None:
            # TODO: Kinda janky. Does this work?
            spec = importlib.util.spec_from_loader(fullname, loader=None)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[fullname] = mod
            exec(self.fbytes, mod.__dict__)
            mod.__file__ = self.filename
            mod.__loader__ = self
            if self.path is not None:
                mod.__path__ = [self.path]

        return mod


class DcodeFinder(object):
    """
    This object goes into the client side import path_hooks
    to allow cobra:// uri's to be added to the import path.
    """
    def __init__(self, proxy):
        self.proxy = proxy

    def find_module(self, fullname, path=None):

        # Check for local modules first...
        localname = fullname.split('.')[-1]
        name, ext = os.path.splitext(localname)

        try:
            fobj, filename, typeinfo = imp.find_module(name, path)
        except ImportError:

            logger.info('Dcode Searching: %s (%s)', name, path)
            pymod = self.proxy.getPythonModule(fullname, path)
            if pymod:
                logger.info('Dcode Loaded: %s', fullname)
                return DcodeLoader(*pymod)


def addDcodeProxy(proxy):
    finder = DcodeFinder(proxy)
    sys.meta_path.append(finder)


def addDcodeUri(uri):
    proxy = cobra.CobraProxy(uri, timeout=120, retrymax=3)
    addDcodeProxy(proxy)


def addDcodeServer(server, port=cobra.COBRA_PORT, ssl=False):
    scheme = "cobra"
    if ssl:
        scheme = "cobrassl"

    uri = "%s://%s:%d/DcodeServer" % (scheme, server, port)
    addDcodeUri(uri)


def enableDcodeServer(daemon=None):
    server = DcodeServer()
    if daemon:
        daemon.shareObject(server, 'DcodeServer')
        return
    cobra.shareObject(server, 'DcodeServer')

def main():
    '''
    Launch a Dcode server including any paths you list on the command line
    '''
    import argparse
    parser = argparse.ArgumentParser(prog='cobraDcode', usage='%(prog)s [options] [additional_path1 [additional_path2] [...]]>')
    parser.add_argument('-P', '--port', dest='port', type=int, default=cobra.COBRA_PORT,
                        help='Listen on what port')
    parser.add_argument('--cacrt', default=None, help='Use TLS encryption: With this Certificate Authority Cert (file)')
    parser.add_argument('--srvcrt', default=None, help='Use TLS encryption: With this Server Cert (file)')
    parser.add_argument('--srvkey', default=None, help='Use TLS encryption: With this Server Key (file)')
    parser.add_argument('path', nargs='*')
    args = parser.parse_args()

    for path in args.path:
        if path not in sys.path:
            logger.info('Adding path "%s" to system path (ie. will serve to Dcode clients)', path)
            sys.path.append(path)

    # first start a cobra server on the specified port
    daemon = cobra.startCobraServer(port=args.port, sslca=args.cacrt, sslcrt=args.srvcrt, sslkey=args.srvkey, msgpack=1)

    # next, enable Dcode
    enableDcodeServer(daemon)

    # wait forever (or until the process is killed)
    daemon.thr.join()




if __name__ == "__main__":
    import envi.common as ecmn
    ecmn.initLogging(logger, logging.DEBUG)
    main()
