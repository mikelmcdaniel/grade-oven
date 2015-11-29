import flask
from OpenSSL import SSL


app = flask.Flask(__name__)


@app.route('/', methods=['POST', 'GET'])
def index():
  return 'Test'


if __name__ == '__main__':
  context = SSL.Context(SSL.TLSv1_METHOD)
  # TODO: generate a legitimate server key and certificate
  context.use_privatekey_file('test_host_dir/tmp/server.key')
  context.use_certificate_file('test_host_dir/tmp/server.crt')
  # TODO: add logging
  app.run(
    host='0.0.0.0', port=4321, debug=True, use_reloader=False,
    use_debugger=False, ssl_context=context)
