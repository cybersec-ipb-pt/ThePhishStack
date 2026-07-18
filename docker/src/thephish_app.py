import eventlet.hubs
eventlet.hubs.use_hub("eventlet.hubs.asyncio")

import eventlet
# Monkeypatches the standard library to replace its key elements with green equivalents (greenlets)
# This is needed for websocket to work and avoid falling back to long polling
eventlet.monkey_patch()

import flask
import flask_socketio
from markupsafe import escape

import list_emails
import case_from_email
import run_analysis
from ws_logger import WebSocketLogger

app = flask.Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False

socketio = flask_socketio.SocketIO(app, path="${ROOT_PATH}/socket.io")
thephish_bp = flask.Blueprint('thephish', __name__, url_prefix='${ROOT_PATH}', static_url_path='/static', static_folder='static')

# The main page
@thephish_bp.route("/", methods=['GET'])
def homepage():
	return flask.render_template("index.html")

@thephish_bp.route('/list', methods = ['GET'])
def obtain_emails_to_analyze():
	# Obtain the list of emails
	emails_info = list_emails.main()
	response = flask.jsonify(emails_info)
	return response

# Analyze the email and obtain the verdict
@thephish_bp.route('/analysis', methods = ['POST'])
def analyze_email():
	# UID of the email to analyze and sid of the client obtained from the request
	mail_uid = escape(flask.request.form.get("mailUID"))
	sid_client = escape(flask.request.form.get("sid"))
	# Instantiate the object used for logging by the other modules
	wsl = WebSocketLogger(socketio, sid_client)
	# Call the modules used to create the case and run the analysis
	new_case_id, external_from_field, subject_field, skip_cortex, auth_results = case_from_email.main(wsl, mail_uid)
	verdict = run_analysis.main(wsl, new_case_id, external_from_field, subject_field, skip_cortex, auth_results)
	response = flask.jsonify(verdict)
	return response

app.register_blueprint(thephish_bp)

# If eventlet or gevent are installed, their wsgi server will be used
# else Werkzeug will be used
if __name__ == "__main__":
	socketio.run(app, host='0.0.0.0', port=8080)