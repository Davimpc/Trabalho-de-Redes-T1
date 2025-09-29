from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer

authorizer = DummyAuthorizer()
# usuário 'user' com senha '12345' e acesso ao diretório atual para fazer a simulação de diferentes máquinas acessando
authorizer.add_user("user", "12345", ".", perm="elradfmw")

handler = FTPHandler
handler.authorizer = authorizer

# usar porta 2121 para não exigir root
server = FTPServer(("0.0.0.0", 2121), handler)
print("FTP server listening on 0.0.0.0:2121 (user=user pass=12345)")
server.serve_forever()