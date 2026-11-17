import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
from server.listener import Listener


def test_listener_calls_listen_with_configured_backlog():
    listener = Listener(host="127.0.0.1", port=0, backlog=42)

    with patch("server.listener.socket.socket") as mock_socket_cls:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        listener.bind_and_listen()

        mock_sock.listen.assert_called_once_with(42)


def test_listener_default_backlog_is_128():
    listener = Listener(host="127.0.0.1", port=0)
    assert listener.backlog == 128
