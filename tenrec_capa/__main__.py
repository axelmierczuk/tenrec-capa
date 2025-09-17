from tenrec.server import Server

from tenrec_capa.plugins import CapaPlugin


def main() -> None:
    # For testing purposes, should not be executed by the server
    plugin = CapaPlugin()
    server = Server(plugins=[plugin], transport="sse")
    server.run()


if __name__ == "__main__":
    main()
