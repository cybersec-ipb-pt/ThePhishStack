import logging.config
import json
import time
import traceback
import re
from bs4 import BeautifulSoup
from datetime import datetime
import dfir_iris_module as df
# Global variable used for logging
log = None
# Global variable used for the configuration, to configure the analyzers level
config, conf_analyzers_level = [{} for _ in range(2)]
dfir_tasks_names = ["[default] ThePhish analysis", "[default] ThePhish notification", "[default] ThePhish result"]

def print_info(wsl, message):
	log.info(message)
	wsl.emit_info(message)

def print_error(wsl, message):
	log.error(message)
	wsl.emit_error(message)

def print_warning(wsl, message):
	log.warning(message)
	wsl.emit_warning(message)

def fetch_module_list(name):
	response = df.get_module_list(config['irisURL'], config['irisApiKey'], config['verify_cert'])

	if any(name in x["module_human_name"] and bool(x["is_active"]) for x in response):
		return True

	return False

def run_module(case, hook_name, module_name, hook_ui_name, hook_type, targets, sleep_time):
	date = (datetime.now()).isoformat()
	df.call_module(config['irisURL'], config['irisApiKey'], str(json.dumps({"hook_name": hook_name, "module_name": module_name, "hook_ui_name": hook_ui_name, "type": hook_type, "targets": targets, "cid": case})), config['verify_cert'])

	while True:
		dim = df.get_dim_task_status(config['irisURL'], config['irisApiKey'], config['verify_cert'])

		if dim is not None and datetime.fromisoformat(dim["date_done"]) > datetime.fromisoformat(date) and dim["case"] == str(f"Case #{case}"):
			break
		else:
			time.sleep(sleep_time)

	return dim["state"]

def update_dfir_task(case, tasks, task_name, task_status_id):
	df.update_task(config['irisURL'], config['irisApiKey'], tasks[task_name][0], str(json.dumps({"cid": case, "task_assignees_id": [config['caseOwnerId']], "task_status_id": task_status_id, "task_title": task_name, "task_description": tasks[task_name][1], "task_tags": tasks[task_name][2]})), config['verify_cert'])

def update_dfir_note(wsl, case, note_id, note_title, description):
	response = df.update_note(config['irisURL'], config['irisApiKey'], note_id, str(json.dumps({"note_title": note_title, "note_content": description, "cid": case})), config['verify_cert'])

	if response.status_code != 200:
		print_error(wsl, 'Cannot update {0} Note: {1} ({2})'.format(note_title, response.status_code, response.text))

		return

	return True

# Send the notification to the user
def notify_start_of_analysis(case, tasks, notes, mail_to, subject_field, wsl):
	# Add a description to the first task that is understood by the Mailer responder and start it
	update_dfir_task(case, tasks, dfir_tasks_names[1], 2)
	note_id = [note['id'] for item in notes if item['name'] == dfir_tasks_names[1] for note in item['notes']][0]
	description = str(f"**Subject:** {str(config['start_notification_subject']).replace('case_id', str(case))}\n**Notification Recipient:** {mail_to}\n\n{str(config['start_notification_message']).replace('inf_email', subject_field)}")

	if update_dfir_note(wsl, case, note_id, "Notification", description) is None:
		return

	if bool(config['send_start_notification']):
		# Check if the responder has been enabled in Cortex
		if fetch_module_list("Cortex Mailer Responder"):
			if run_module(case, "on_manual_trigger_note", config['cortexmaileresponder'], "Send Mailer notification", "note", [note_id], 2) == 'success':
				print_info(wsl, 'Notification mail sent')
			else:
				print_warning(wsl, 'Something went wrong with the Mailer responder')
		else:
			print_warning(wsl, 'The Mailer responder is not active')
	else:
		print_info(wsl, f"Not sending start analysis notification to {mail_to}")

	# Close the task
	update_dfir_task(case, tasks, dfir_tasks_names[1], 4)

# Start the analyzers on the IOCs
def analyze_observables(case, tasks, notes, skip_cortex, auth_results, wsl):
	# Check if the Cortex Analyzer module has been enabled in DFIR-IRIS
	if not fetch_module_list("Cortex Analyzer"):
		print_error(wsl, "Cortex Analyzer not present in the list of Modules enabled. Can not proceed with analisys.")

		return

	# Initialize the number of malicious and suspicious IOCs to 0
	malicious_observables, suspicious_observables = 0, 0
	verdicts = {}
	# Obtain the ioc list from the case
	observables = df.get_ioc_list(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": case})), config['verify_cert'])

	if observables.status_code != 200:
		print_error(wsl, 'Cannot fecth IOC List: {0} ({1})'.format(observables.status_code, observables.text))

		return

	# Start all the applicable analyzers for IOCs not in skip_cortex
	for res in observables.json()["data"]["ioc"]:
		if res["ioc_value"] in skip_cortex:
			print_info(wsl, f"Skipping analysis for IOC: {res['ioc_value']}")
			continue

		df.update_ioc(config['irisURL'], config['irisApiKey'], res["ioc_id"], str(json.dumps({"cid": case, "ioc_value": res["ioc_value"], "ioc_tlp_id": res["ioc_tlp_id"], "ioc_type_id": res["ioc_type_id"], "ioc_description": res["ioc_description"], "ioc_tags": ""})), config['verify_cert'])
		print_info(wsl, f"Starting analysis for IOC: {res['ioc_value']}")

		if run_module(case, "on_manual_trigger_ioc", config['cortexanalyzer'], "Run Cortex Analyzers", "ioc", [res["ioc_id"]], 5) == 'success':
			print_info(wsl, f"Finish analysis for IOC: {res['ioc_value']}")
			r = df.get_ioc(config['irisURL'], config['irisApiKey'], res["ioc_id"], str(json.dumps({"cid": case})), config['verify_cert'])

			if r.json()["data"]["custom_attributes"]:
				soup = BeautifulSoup(str(r.json()["data"]["custom_attributes"]["CORTEX Reports"]["HTML report"]["value"]), "html.parser")
				json_divs = soup.find_all("div", id=re.compile(r"^cortexanalyzer_raw_ace_"))
				extracted_reports, verdicts[res["ioc_value"]] = [{} for _ in range(2)]
				# Count the number of malicious and suspicious reports for each ioc
				malicious_reports, suspicious_reports = 0, 0

				for div in json_divs:
					div_id = div.get("id")
					raw_text = div.string.strip()

					try:
						parsed_json = json.loads(raw_text)
						extracted_reports[div_id.replace("cortexanalyzer_raw_ace_", "")] = parsed_json
					except json.JSONDecodeError:
						pass

				# For each analyzer, extract the verdict.
				for k in extracted_reports:
					level = 'info'

					if (summary := extracted_reports[k].get('summary')) and (taxonomies := summary.get('taxonomies')):
						if taxonomies:
							# Handle Pulsedive
							# Many taxonomies are created, only the last one is needed
							if(k == 'Pulsedive_GetIndicator_1_0'):
								level = taxonomies[-1].get('level', 'info')
							# Handle IPVoid
							# Many taxonomies are created, only the last one is needed
							elif (k == 'IPVoid_1_0'):
								level = taxonomies[-1].get('level', 'info')
							# Handle Shodan
							# Many taxonomies are created, only the last one is needed
							# The other analyzers based on shodan only give "info" as level
							elif (k in ['Shodan_Host_1_0', 'Shodan_Host_History_1_0']):
								level = taxonomies[-1].get('level', 'info')
							# Handle SpamhausDBL
							# The first taxonomy contains the return code that if it is among the codes listed below it means that the level should be malicious
							elif (k == 'SpamhausDBL_1_0'):
								if(taxonomies[0].get('value', 'NXDOMAIN') in ['127.0.1.2', '127.0.1.4', '127.0.1.5', '127.0.1.6', '127.0.1.102', '127.0.1.103', '127.0.1.104', '127.0.1.105', '127.0.1.106']):
									level = 'malicious'
							elif (k == 'DShield_lookup_1_0' and taxonomies[0].get('level', 'info') == 'safe' and ('0 attack(s)' not in taxonomies[0].get('value') or '0 threatfeed(s)' not in taxonomies[0].get('value'))):
								level = 'suspicious'
							# For all the other analyzers uses the first taxonomy
							else:
								level = taxonomies[0].get('level', 'info')

					# Handle URLhaus
					# md5_hash and sha256_hash are supported only for payload search and not also for URL or hosts (IP, domains)
					# Without this modification it is always given a level of "info" even though it should be "malicious"
					# So, if "info" is obtained, check in the full report if there is a threat and, if so, set the level to "malicious"
					if (k == 'URLhaus_2_0' and extracted_reports[k]['full']['query_status'] == 'ok' and extracted_reports[k]['full'].get('threat')):
						level = 'malicious'

					# Handle analyzers levels
					# Often happens that the level given by an analyzer is too high for some or all the ioc types on which it is applicable, leading to false positives
					# It is then used a configuration file which is a dictionary containing, for each analyzer that has to be modified:
					# - dataType: types of the IOCs on which to apply the modification
					# - level mapping
					if k in conf_analyzers_level:
						if res["ioc_type"] == "ip-any":
							res["ioc_type"] = "ip" 
						if res["ioc_type"] == "email":
							res["ioc_type"] = "mail"
						if res["ioc_type"] in conf_analyzers_level[k]['dataType']:
							level = conf_analyzers_level[k]['levelMapping'][level]

					verdicts[res["ioc_value"]][k] = level

					if level == 'malicious':
						malicious_reports += 1
					elif level == 'suspicious':
						suspicious_reports += 1

					print_info(wsl, f"Verdict for {res['ioc_type']} {res['ioc_value']} from analyzer {k}: {level}")

				# If the number of malicious reports is > 0 for this ioc, the ioc is malicious
				if malicious_reports > 0:
					malicious_observables += 1

				# If the number of suspicious reports is > 0 for this ioc, the ioc is suspicious
				if suspicious_reports > 0:
					suspicious_observables += 1
		else:
			print_warning(wsl, f"Something went wrong with analysis for IOC: {res['ioc_value']}")

	if len(verdicts) == 0:
		print_error(wsl, "No reports were generated from Cortex analysis. Unable to proceed.")

		return

	print_info(wsl, "All the analysis jobs terminated.")
	description = str(f"Automated analysis results:\n\n```{str(json.dumps(verdicts, indent=4)).replace('": "', ' verdict": "')}\n```")

	# If there is at least one malicious ioc, then the email is malicious
	if malicious_observables > 0:
		verdict = "Malicious"
	# If there is at least one suspicious ioc, then the email is suspicious
	elif suspicious_observables > 0:
		verdict = "Suspicious"
	# Else the email is safe, depending on the Email Authentication-Results header
	else:
		print_info(wsl, "Analyzers classified the email as safe. Checking Email Authentication-Results header for additional information.")

		if auth_results["dmarc"] == "fail":
			verdict = "Malicious"
			print_info(wsl, "DMARC explicit failure: The sender identity is actively spoofing a protected domain.")
			description = str(description + "\n\nDMARC explicit failure: The sender identity is actively spoofing a protected domain.")
		elif auth_results["spf"] == "fail" and auth_results["dkim"] == "fail":
			verdict = "Malicious"
			print_info(wsl, "Both SPF and DKIM signatures failed validation.")
			description = str(description + "\n\nBoth SPF and DKIM signatures failed validation.")
		elif auth_results["dmarc"] in ["none", "permerror", "temperror", "not found"]:
			verdict = "Suspicious"
			print_info(wsl, f"Weak domain configuration: DMARC status resolved to '{auth_results['dmarc']}'.")
			description = str(description + f"\n\nWeak domain configuration: DMARC status resolved to '{auth_results['dmarc']}'.")
		elif auth_results["spf"] == "softfail" and auth_results["dkim"] in ["fail", "none", "not found"]:
			verdict = "Suspicious"
			print_info(wsl, "SPF returned softfail with no valid DKIM signature present.")
			description = str(description + "\n\nSPF returned softfail with no valid DKIM signature present.")
		else:
			verdict = "Safe"

	print_info(wsl, "The email has been classified as " + verdict)
	# Update Analysis Note
	note_id = [note['id'] for item in notes if item['name'] == dfir_tasks_names[0] for note in item['notes']][0]

	if update_dfir_note(wsl, case, note_id, "Analysis", description) is None:
		return

	# Close the second task
	update_dfir_task(case, tasks, dfir_tasks_names[0], 4)

	return verdict

def terminate_case(case, tasks, notes, mail_to, verdict, subject_field, wsl):
	# Start the third task
	update_dfir_task(case, tasks, dfir_tasks_names[2], 2)
	# Add a description to the third task that is understood by the Mailer responder
	note_id = [note['id'] for item in notes if item['name'] == dfir_tasks_names[2] for note in item['notes']][0]
	description = str(f"**Subject:** {str(config['send_result_subject']).replace('case_id', str(case))}\n**Notification Recipient:** {mail_to}\n\n{str(config['verdict_messages'][str(verdict).lower()]).replace('inf_email', subject_field)}")

	if update_dfir_note(wsl, case, note_id, "Result", description) is None:
		return

	# If the verdict is final close the task and the case, else leave the third task and the case open
	if verdict != "Suspicious":
		if verdict == 'Malicious':
			resolution_status = 'True positive without impact'
		elif verdict == 'Safe':
			resolution_status = 'False positive'

		if (verdict == 'Malicious' and bool(config['send_malicious_result_notification'])) or (verdict == 'Safe' and bool(config['send_safe_result_notification'])):
			# Check if the responder has been enabled in DFIR-IRIS
			if fetch_module_list("Cortex Mailer Responder"):
				if run_module(case, "on_manual_trigger_note", config['cortexmaileresponder'], "Send Mailer notification", "note", [note_id], 2) == 'success':
					print_info(wsl, 'Response mail sent')
				else:
					print_warning(wsl, 'Something went wrong with the Mailer responder')
			else:
				print_warning(wsl, 'The Mailer responder is not active')
		else:
			print_info(wsl, f"Not sending result response notification to {mail_to}")

		# Close the tasks
		for task in tasks:
			if task == dfir_tasks_names[0] or task == dfir_tasks_names[1]:
				continue

			update_dfir_task(case, tasks, task, 4)

		# Close the case
		df.update_case(config['irisURL'], config['irisApiKey'], case, str(json.dumps({"reviewer_id": config['caseReviewerId'], "status_id": df.status[resolution_status]})), config['verify_cert'])
		df.update_summary(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": case, "case_description": "Automated analysis"})), config['verify_cert'])
		df.review_case(config['irisURL'], config['irisApiKey'], case, str(json.dumps({"action": "start"})), config['verify_cert'])
		df.review_case(config['irisURL'], config['irisApiKey'], case, str(json.dumps({"action": "done"})), config['verify_cert'])
		df.close_case(config['irisURL'], config['irisApiKey'], case, config['verify_cert'])
		print_info(wsl, "Case resolved as " + resolution_status)

# Main function called from outside
# The wsl is not a global variable to support multiple tabs
# The mail_to parameter is the email address of the user to send notifications to
def main(wsl, case, mail_to, subject_field, skip_cortex, auth_results):
	global config
	global log
	global conf_analyzers_level

	# Logging configuration
	try:
		with open('logging_conf.json') as log_conf:
			log_conf_dict = json.load(log_conf)
			logging.config.dictConfig(log_conf_dict)
	except Exception:
		print("[ERROR]_[run_analysis]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return

	log = logging.getLogger(__name__)

	# DFIR-IRIS, DIM and Case Notification configuration
	try:
		with open("configuration.json") as conf_file:
			conf_dict = json.load(conf_file)
			config['irisURL'] = conf_dict['iris']['url']
			config['irisApiKey'] = conf_dict['iris']['apikey']
			config['verify_cert'] = conf_dict['iris']['verify_cert']
			config['cortexanalyzer'] = conf_dict['dim']['cortex_analyzer_module_name']
			config['cortexmaileresponder'] = conf_dict['dim']['cortex_mailer_responder_module_name']
			config['caseReviewerId'] = conf_dict['case']['reviewer_id']
			config['caseOwnerId'] = conf_dict['case']['owner_id']
			config['send_start_notification'] = conf_dict['case']['send_start_notification']
			config['start_notification_subject'] = conf_dict['case']['start_notification_subject']
			config['start_notification_message'] = conf_dict['case']['start_notification_message']
			config['send_malicious_result_notification'] = conf_dict['case']['send_malicious_result_notification']
			config['send_safe_result_notification'] = conf_dict['case']['send_safe_result_notification']
			config['send_result_subject'] = conf_dict['case']['send_result_subject']
			config['verdict_messages'] = {
				"malicious": conf_dict['case']['verdict_messages']['malicious'],
				"suspicious": conf_dict['case']['verdict_messages']['suspicious'],
				"safe": conf_dict['case']['verdict_messages']['safe']
			}
	except Exception: 
		log.error("Error while trying to open the file 'configuration.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'configuration.json'")
		return

	# Read the configuration file for the analyzers levels modification
	try:
		with open("analyzers_level_conf.json") as conf_file:
			conf_analyzers_level = json.load(conf_file)
	except Exception: 
		log.error("Error while trying to open the file 'analyzers_level_conf.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'analyzers_level_conf.json'")
		return

	# Obtain the IDS of the three task of the case
	tasks = {}
	response = df.get_tasks(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": case})), config['verify_cert'])
	notes = df.get_notes_group(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": case})), config['verify_cert'])

	if notes.status_code != 200:
		print_error(wsl, 'Cannot fecth Notes Groups: {0} ({1})'.format(notes.status_code, notes.text))

		return

	for x in response.json()["data"]["tasks"]:
		tasks[x["task_title"]] = [x["task_id"], x["task_description"], x["task_tags"]]

	# Call the notify_start_of_analysis function
	try:
		notify_start_of_analysis(case, tasks, notes.json()["data"], mail_to, subject_field, wsl)
	except Exception:
		log.error("Error while trying to notify the start of analysis: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to notify the start of analysis")
		return

	# Call the analyze_observables function
	try:
		verdict = analyze_observables(case, tasks, notes.json()["data"], skip_cortex, auth_results, wsl)
	except Exception:
		log.error("Error during the analysis task: {}".format(traceback.format_exc()))
		wsl.emit_error("Error during the analysis task")
		return

	# Call the terminate_analysis function
	try:
		terminate_case(case, tasks, notes.json()["data"], mail_to, verdict, subject_field, wsl)
	except Exception:
		log.error("Error during the termination of the analysis: {}".format(traceback.format_exc()))
		wsl.emit_error("Error during the termination of the analysis")
		return

	return verdict