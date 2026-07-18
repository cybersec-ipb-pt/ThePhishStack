import logging.config
import imaplib
import io
import json
import base64
import hashlib
import re
import email
import emoji
import urllib.parse
import traceback
import ioc_finder
import dfir_iris_module as df
# Global variable used for logging
log = None
# Global variable used for the configuration, variable used for the whitelist
config, whitelist = [{} for _ in range(2)]
# Global variable used for the skipping Cortex IOC analisys
skip_cortex = []

def print_info(wsl, message):
	log.info(message)
	wsl.emit_info(message)

def print_error(wsl, message):
	log.error(message)
	wsl.emit_error(message)

def proc_filters(vlaue, wsl):
	if not config[f"{vlaue}_skip_ioc"]:
		print_info(wsl, f"No {vlaue} IOC filter(s) applied.")
	else:
		if "," in  config[f"{vlaue}_skip_ioc"]:
			config[f"{vlaue}_skip_ioc"] = config[f"{vlaue}_skip_ioc"].split(',')
		else:
			config[f"{vlaue}_skip_ioc"] = [config[f"{vlaue}_skip_ioc"]]

		print_info(wsl, f"The following {vlaue} will be skipped during IOC analysis:")
		print_info(wsl, config[f"{vlaue}_skip_ioc"])

def connect_to_imap_server(wsl):
	# Create the connection to the IMAP server using host and port
	connection = imaplib.IMAP4_SSL(config['imapHost'], config['imapPort'])
	# Log in using username and password
	connection.login(config['imapUser'],config['imapPassword'])
	print_info(wsl, 'Connected to email {0} server {1}:{2}/{3}'.format(config['imapUser'], config['imapHost'], config['imapPort'], config['imapFolder']))

	return connection

# Check if an IOC is whitelisted with an exact match or with a regex match
def is_whitelisted(obs_type, obs_value):
	found = False

	if ((not found) and (obs_value in whitelist[obs_type+'Exact'])):
		found = True
	if ((not found) and (obs_type == 'domain')):
		for regex in whitelist['regexDomainsInSubdomains']:
			if re.search(regex, obs_value):
				found = True
	if ((not found) and (obs_type == 'url')):
		for regex in whitelist['regexDomainsInURLs']:
			if re.search(regex, obs_value):
				found = True
	if ((not found) and (obs_type == 'mail')):
		for regex in whitelist['regexDomainsInEmails']:
			if re.search(regex, obs_value):
				found = True
	if ((not found) and (obs_type not in ['hash', 'filetype'])):
		for regex in whitelist[obs_type+'Regex']:
			if re.search(regex, obs_value):
				found = True

	return found

# Use the ioc-finder module to extract observables from a string buffer and add to the list only if they are not whitelisted
def search_observables(buffer, wsl):
	global skip_cortex
	observables = []
	iocs = {}
	iocs['email_addresses'] = ioc_finder.parse_email_addresses(buffer)
	iocs['ipv4s'] = ioc_finder.parse_ipv4_addresses(buffer)
	iocs['ipv6s'] = ioc_finder.parse_ipv6_addresses(re.sub("IPv6:", "", str(buffer), flags=re.IGNORECASE))
	iocs['domains'] = ioc_finder.parse_domain_names(buffer)
	# Option to parse URLs without a scheme (e.g. without https://)
	iocs['urls'] = ioc_finder.parse_urls(buffer, parse_urls_without_scheme=False)

	for mail in iocs['email_addresses']:
		if is_whitelisted('mail', mail):
			print_info(wsl, "Skipped whitelisted observable mail: {0}".format(mail))
		else:
			print_info(wsl, "Found observable mail: {0}".format(mail))
			observables.append({'type': 'email', 'value': mail})

			if config['email_skip_ioc'] and any(ioc.strip() in mail for ioc in config['email_skip_ioc']):
				skip_cortex.append(mail)

	for ip in iocs['ipv4s']:
		if is_whitelisted('ip', ip):
			print_info(wsl, "Skipped whitelisted observable IPv4: {0}".format(ip))
		else:
			print_info(wsl, "Found observable IPv4: {0}".format(ip))
			observables.append({'type': 'ip-any', 'value': ip})

	for ip in iocs['ipv6s']:
		if is_whitelisted('ip', ip):
			print_info(wsl, "Skipped whitelisted observable IPv6: {0}".format(ip))
		else:
			print_info(wsl, "Found observable IPv6: {0}".format(ip))
			observables.append({'type': 'ip-any', 'value': ip})

	for domain in iocs['domains']:
		if is_whitelisted('domain', domain):
			print_info(wsl, "Skipped whitelisted observable domain: {0}".format(domain))
		else:
			print_info(wsl, "Found observable domain: {0}".format(domain))
			observables.append({'type': 'domain', 'value': domain})

			if config['domain_skip_ioc'] and any(ioc.strip() in domain for ioc in config['domain_skip_ioc']):
				skip_cortex.append(domain)

	for url in iocs['urls']:
		if is_whitelisted('url', url):
			print_info(wsl, "Skipped whitelisted observable url: {0}".format(url))
		else:
			print_info(wsl, "Found observable url: {0}".format(url))
			observables.append({'type': 'url', 'value': url})

	skip_cortex = list(set(skip_cortex))

	return observables

# Use the mail UID of the selected email to fetch only that email from the mailbox
def obtain_eml(connection, mail_uid, wsl):
	# Read all the unseen emails from this folder
	connection.select(config['imapFolder'])
	typ, dat = connection.search(None, '(UNSEEN)')

	# The dat[0] variable contains the IDs of all the unread emails
	# The IDs are obtained by using the split function and the length of the array is the number of unread emails
	# If the selected mail uid is present in the list, then process only that email
	if mail_uid.encode() in dat[0].split():
		typ, dat = connection.fetch(mail_uid.encode(), '(RFC822)')

		if typ != 'OK':
			print_error(wsl, dat[-1])

		message = dat[0][1]
		# The fetch operation flags the message as seen by default
		print_info(wsl, "Message {0} flagged as read".format(mail_uid))
		# Obtain the From field of the external email that will be used to send the verdict to the user
		msg = email.message_from_bytes(message)
		decode = email.header.decode_header(msg['From'])[0]

		if decode[1] is not None:
			external_from_field = decode[0].decode(decode[1])
		else:
			external_from_field = str(decode[0])

		parsed_from_field = email.utils.parseaddr(external_from_field)

		if len(parsed_from_field) > 1:
			external_from_field = parsed_from_field[1]

		# Variable used to detect the mimetype of the email parts
		mimetype = None
		# Variable that will contain the internal EML file
		internal_msg = None

		# Walk the multipart structure of the email (now only the EML part is needed)
		for part in msg.walk():
			mimetype = part.get_content_type()

			# If the content type of this part is the rfc822 message, then stop because the EML attachment is the last part
			# If there is any other part after the rfc822 part, then it may be related to the internal email, so it must not be considered
			# Both message/rfc822 and application/octet-stream types are considered due to differences in how the attachment is handled by different mail clients
			if mimetype in ['application/octet-stream', 'message/rfc822']:
				# Obtain the internal EML file in both cases
				if mimetype == 'application/octet-stream':
					eml_payload = part.get_payload(decode=1)
					internal_msg = email.message_from_bytes(eml_payload)
				elif mimetype == 'message/rfc822':
					eml_payload = part.get_payload(decode=0)[0]

					try:
						internal_msg = email.message_from_string(base64.b64decode(str(eml_payload)).decode())
					except Exception:
						internal_msg = eml_payload

				# If the EML attachment has been found, then break the for
				break

		return internal_msg, external_from_field
	else:
		# Handle multiple analysts that select the same email from more than one tab
		print_error(wsl, "The email with UID {} has already been analyzed. Please refresh the page and retry.".format(mail_uid))

# Parse the EML file and extract the observables
def parse_eml(internal_msg, wsl):
	# Obtain the subject of the internal email
	# This is not straightforward since the subject might be splitted in two or more parts
	decode_subj = email.header.decode_header(internal_msg['Subject'])
	decoded_elements_subj = []

	for decode_elem in decode_subj:
		if decode_elem[1] is not None:
			if str(decode_elem[1]) == 'unknown-8bit':
				decoded_elements_subj.append(decode_elem[0].decode())
			else:
				decoded_elements_subj.append(decode_elem[0].decode(decode_elem[1]))
		else:
			if(isinstance(decode_elem[0], str)):
				decoded_elements_subj.append(str(decode_elem[0]))
			else:
				decoded_elements_subj.append(decode_elem[0].decode())

		subject_field = ''.join(decoded_elements_subj)

	print_info(wsl, "Analyzing attached message with subject: {}".format(subject_field))
	# List of attachments of the internal email, of attachment hashes, of observables found in the body of the internal email
	attachments, hashes_attachments, observables_body = [[] for _ in range(3)]
	# Dictionary containing a list of observables found in each header field
	observables_header = {}
	# List of header fields to consider when searching for observables in the header
	header_fields_list = [
		'To',
		'From',
		'Sender',
		'Cc',
		'Delivered-To',
		'Return-Path',
		'Reply-To',
		'Bounces-to',
		'Received',
		'X-Received',
		'X-OriginatorOrg',
		'X-Sender-IP',
		'X-Originating-IP',
		'X-SenderIP',
		'X-Originating-Email'
	]
	# Dictionary containing the status of DKIM, DMARC and SFP found on the email
	auth_results = dict.fromkeys(["spf", "dkim", "dmarc"], "Not Found")
	# Extract header fields
	parser = email.parser.HeaderParser()
	header_fields = parser.parsestr(internal_msg.as_string())
	auth_headers = header_fields.get_all('Authentication-Results', [])
	# Search the observables in the values of all the selected header fields
	# Since a field may appear more than one time (e.g. Received:), the lists need to be initialized and then extended
	i = 0

	for header in auth_headers:
		header_lower = header.lower()

		if 'spf=' in header_lower:
			auth_results["spf"] = header_lower.split('spf=')[1].split()[0].strip(';')
		if 'dkim=' in header_lower:
			auth_results["dkim"] = header_lower.split('dkim=')[1].split()[0].strip(';')
		if 'dmarc=' in header_lower:
			auth_results["dmarc"] = header_lower.split('dmarc=')[1].split()[0].strip(';')

	while i < len(header_fields.keys()):
		if header_fields.keys()[i] in header_fields_list:
			if not observables_header.get(header_fields.keys()[i]):
				observables_header[header_fields.keys()[i]] = []

			observables_header[header_fields.keys()[i]].extend(search_observables(header_fields.values()[i], wsl))

		i+=1

	# Walk the multipart structure of the internal email
	for part in internal_msg.walk():
		mimetype = part.get_content_type()
		content_disposition = part.get_content_disposition()

		if content_disposition != "attachment":
			# Extract the observables from the body (from both text/plain and text/html parts) using the search_observables function
			if mimetype == "text/plain":
				try:
					body = part.get_payload(decode=True).decode()
				except UnicodeDecodeError:
					body = part.get_payload(decode=True).decode('ISO-8859-1')

				observables_body.extend(search_observables(body, wsl))
			elif mimetype == "text/html":
				try:
					html = part.get_payload(decode=True).decode()
				except UnicodeDecodeError:
					html = part.get_payload(decode=True).decode('ISO-8859-1')

				# Handle URL encoding
				html_urldecoded = urllib.parse.unquote(html.replace("&amp;", "&"))
				observables_body.extend(search_observables(html_urldecoded, wsl))
		# Extract attachments
		else:
			filename = part.get_filename()

			if filename and mimetype:
				# Add the attachment if it is not whitelisted (in terms of filename or filetype)
				if is_whitelisted('filename', filename) or is_whitelisted('filetype', mimetype):
					print_info(wsl, "Skipped whitelisted observable file: {0}".format(filename))
				else:
					inmem_file = io.BytesIO(part.get_payload(decode=1))
					attachments.append((inmem_file, filename))
					print_info(wsl, "Found observable file: {0}".format(filename))
					# Calculate the hash of the just found attachment
					sha256 = hashlib.sha256()
					sha256.update(part.get_payload(decode=1))
					hash_attachment = sha256.hexdigest()

					if is_whitelisted('hash', hash_attachment):
						print_info(wsl, "Skipped whitelisted observable hash: {0}".format(hash_attachment))
					else:
						hashes_attachments.append(filename)
						print_info(wsl, "Found observable hash {0} calculated from file: {1}".format(hash_attachment, filename))

	# Create a tuple containing the eml file and the name it should have as an IOC
	filename = subject_field + ".eml"
	inmem_file = io.BytesIO()
	gen = email.generator.BytesGenerator(inmem_file)
	gen.flatten(internal_msg)
	eml_file_tuple = (inmem_file, filename)

	# Workaround to prevent HTML tags to appear inside the URLs (splits on < or >)
	for observable_body in observables_body:
		if observable_body['type'] == "url":
			observable_body['value'] = observable_body['value'].replace(">", "<").split("<")[0]

	return subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, auth_results

def fetch_dfir_template(wsl):
	templates = {}
	response = df.get_templates(config['irisURL'], config['irisApiKey'], config['verify_cert'])

	if response.status_code != 200:
		print_error(wsl, 'Cannot fetch templates: {0} ({1})'.format(response.status_code, response.text))

		return

	for x in response.json()["data"]:
		templates[x["display_name"]] = [x["id"], x["description"]]

	if "ThePhish" not in templates:
		with open("CaseTemplate.json", "r") as file:
			data = json.dumps(json.load(file))
			data = json.dumps({"case_template_json": data})
			response = df.upload_template(config['irisURL'], config['irisApiKey'], str(data), config['verify_cert'])

		if response.status_code == 200:
			print_info(wsl, 'Template ThePhish created successfully')
		else:
			print_error(wsl, 'Cannot create template: {0} ({1})'.format(response.status_code, response.text))

			return

		response = df.get_templates(config['irisURL'], config['irisApiKey'], config['verify_cert'])

		for x in response.json()["data"]:
			templates[x["display_name"]] = [x["id"], x["description"]]

	return templates

def update_dfir_evidence(wsl, caseid, evidence_type, filename, cannot_add_ioc_log_fmt):
	response = df.get_evidence_list(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": caseid})), config['verify_cert'])
	response = df.update_evidence(config['irisURL'], config['irisApiKey'], response.json()["data"]["evidences"][0]["id"], str(json.dumps({"cid": caseid, "filename": response.json()["data"]["evidences"][0]["filename"], "file_size": response.json()["data"]["evidences"][0]["file_size"], "file_hash": response.json()["data"]["evidences"][0]["file_hash"], "file_description": "Imported from datastore.", "custom_attributes": None, "type_id": evidence_type["Generic - Data blob"]})), config['verify_cert'])

	if response.status_code == 200:
		print_info(wsl, 'Added IOC file {0} to case {1}'.format(filename, caseid))
	else:
		log.debug(cannot_add_ioc_log_fmt.format(filename, response.status_code, response.text))

# Create the case on DFIR-IRIS and add the observables to it
def create_case(subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, wsl):
	# Create the case template first if it does not exist
	classifications, tasks, iocs_types, iocs, evidence_type = [{} for _ in range(5)]
	templates = fetch_dfir_template(wsl)

	if templates is None:
		return

	# Retrive case classifications
	response = df.get_classifications(config['irisURL'], config['irisApiKey'], config['verify_cert'])

	if response.status_code != 200:
		print_error(wsl, 'Cannot retrive case classifications: {0} ({1})'.format(response.status_code, response.text))

		return

	for x in response.json()["data"]:
		classifications[x["name"]] = x["id"]

	# Create the case on DFIR-IRIS
	# The emojis are removed to prevent problems when exporting the case to MISP
	response = df.create_case(config['irisURL'], config['irisApiKey'], str(json.dumps({"case_soc_id": "", "case_customer": int(config['caseCustomerId']), "case_name": emoji.replace_emoji(subject_field), "case_description": templates["ThePhish"][1], "case_template_id": str(templates["ThePhish"][0]), "classification_id": classifications["phishing"]})), config['verify_cert'])

	if response.status_code == 200:
		caseid = response.json()["data"]["case_id"]
		print_info(wsl, 'Created case {}'.format(caseid))
		response = df.update_case(config['irisURL'], config['irisApiKey'], caseid, str(json.dumps({"case_name":emoji.replace_emoji(subject_field), "reviewer_id": config['caseReviewerId'], "owner_id": config['caseOwnerId'], "status_id": df.status["Not applicable"], "severity_id": df.severity[config['severity']], "case_tags": "Phishing,ThePhish"})), config['verify_cert'])

		if response.status_code != 200:
			print_error(wsl, 'Cannot update case: {0} ({1})'.format(response.status_code, response.text))

			return

		response = df.get_tasks(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": caseid})), config['verify_cert'])

		for x in response.json()["data"]["tasks"]:
			tasks[x["task_title"]] = [x["task_id"], x["task_description"], x["task_tags"]]

		task_name = str("[default] ThePhish analysis")
		df.update_task(config['irisURL'], config['irisApiKey'], tasks[task_name][0], str(json.dumps({"cid": caseid, "task_assignees_id": [config['caseOwnerId']], "task_status_id": 2, "task_title": task_name, "task_description": tasks[task_name][1], "task_tags": tasks[task_name][2]})), config['verify_cert'])
		response = df.get_ioc_types(config['irisURL'], config['irisApiKey'], config['verify_cert'])

		for x in response.json()["data"]:
			iocs_types[x["type_name"]] = x["type_id"]

		# Add observables found in the mail header, in the mail body and hashes of the attachments
		for header_field in observables_header:
			for observable_header in observables_header[header_field]:
				if observable_header['value'] not in iocs.keys():
					iocs[observable_header['value']] = [observable_header['type'], 'Found in the {} field of the email header'.format(header_field)]

		for observable_body in observables_body:
			if observable_body['value'] not in iocs.keys():
				iocs[observable_body['value']] = [observable_body['type'], 'Found in the email body']

		for key in iocs.keys():
			response = df.add_ioc(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": caseid, "ioc_type_id": iocs_types[iocs[key][0]], "ioc_tlp_id": 2, "ioc_value": key, "ioc_description": iocs[key][1], "ioc_tags": ""})), config['verify_cert'])

			if response.status_code == 200:
				print_info(wsl, 'Added IOC {0}: {1} to case {2}'.format(iocs[key][0], key, caseid))
			else:
				log.debug('Cannot add IOC {0}: {1} - {2} ({3})'.format(iocs[key][0], key, response.status_code, response.text))

		# Add attachments
		if attachments or eml_file_tuple:
			cannot_add_ioc_log_fmt = 'Cannot add IOC: file {0} - {1} ({2})'
			response = df.get_evidence_type(config['irisURL'], config['irisApiKey'], config['verify_cert'])

			for x in response.json()["data"]:
				evidence_type[x["name"]] = x["id"]

			response = df.get_datastore_tree(config['irisURL'], config['irisApiKey'], str(json.dumps({"cid": caseid})), config['verify_cert'])
			root_key = next(iter(response.json()["data"]))
			children = response.json()["data"][root_key].get('children', {})
			evidence_key = str(next((key for key, value in children.items() if value.get('name') == 'Evidences'), None)).split("d-")[1]

		for attachment in attachments:
			if attachment[1] in hashes_attachments:
				response = df.upload_file(config['irisURL'], config['irisApiKey'], evidence_key, caseid, {"file_original_name": str(attachment[1]), "file_description": None, "file_password": None, "file_tags": None, "file_is_evidence": "y", "file_is_ioc": "y"}, {"file_content": (attachment[1], attachment[0])}, config['verify_cert'])
			else:
				response = df.upload_file(config['irisURL'], config['irisApiKey'], evidence_key, caseid, {"file_original_name": str(attachment[1]), "file_description": None, "file_password": None, "file_tags": None, "file_is_evidence": "y"}, {"file_content": (attachment[1], attachment[0])}, config['verify_cert'])

			if response.status_code == 200:
				update_dfir_evidence(wsl, caseid, evidence_type, attachment[1], cannot_add_ioc_log_fmt)
			else:
				log.debug(cannot_add_ioc_log_fmt.format(attachment[1], response.status_code, response.text))

		# Add eml file (using the tuple)
		if eml_file_tuple:
			eml_file_tuple[0].seek(0)
			response = df.upload_file(config['irisURL'], config['irisApiKey'], evidence_key, caseid, {"file_original_name": str(eml_file_tuple[1]), "file_description": None, "file_password": None, "file_tags": None, "file_is_evidence": "y", "file_is_ioc": "y"}, {"file_content": (eml_file_tuple[1], eml_file_tuple[0])}, config['verify_cert'])

			if response.status_code == 200:
				update_dfir_evidence(wsl, caseid, evidence_type, eml_file_tuple[1], cannot_add_ioc_log_fmt)
			else:
				log.debug(cannot_add_ioc_log_fmt.format(eml_file_tuple[1], response.status_code, response.text))
	else:
		print_error(wsl, 'Cannot create case: {0} ({1})'.format(response.status_code, response.text))

		return

	# Return the id of the just created case on which to run the analysis
	return caseid

# Main function called from outside
# The wsl is not a global variable to support multiple tabs
def main(wsl, mail_uid):
	global config
	global whitelist
	global log
	global skip_cortex

	# Logging configuration
	try:
		with open('logging_conf.json') as log_conf:
			log_conf_dict = json.load(log_conf)
			logging.config.dictConfig(log_conf_dict)
	except Exception:
		print("[ERROR]_[list_emails]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return

	log = logging.getLogger(__name__)

	try:
		with open('configuration.json') as conf_file:
			conf_dict = json.load(conf_file)
			# IOC analysis filter
			config['email_skip_ioc'] = conf_dict['skip_ioc_analysis']['emails']
			config['domain_skip_ioc'] = conf_dict['skip_ioc_analysis']['domains']
			# IMAP configuration
			config['imapHost'] = conf_dict['imap']['host']
			config['imapPort'] = int(conf_dict['imap']['port'])
			config['imapUser'] = conf_dict['imap']['user']
			config['imapPassword'] = conf_dict['imap']['password']
			config['imapFolder'] = conf_dict['imap']['folder']
			# IRIS configuration
			config['irisURL'] = conf_dict['iris']['url']
			config['irisApiKey'] = conf_dict['iris']['apikey']
			config['verify_cert'] = conf_dict['iris']['verify_cert']
			# New case configuration
			config['caseCustomerId'] = conf_dict['case']['customer_id']
			config['caseReviewerId'] = conf_dict['case']['reviewer_id']
			config['caseOwnerId'] = conf_dict['case']['owner_id']
			config['severity'] = conf_dict['case']['severity']
	except Exception:
		log.error("Error while trying to open the file 'configuration.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'configuration.json'")

		return

	# Read the whitelist file, which is composed by various parts:
	# - The exact matching part
	# - The regex matching part
	# - Three lists of domains that are used to whitelist subdomains, URLs and email addresses that contain them
	try:
		with open('whitelist.json') as whitelist_file:
			whitelist_dict = json.load(whitelist_file)
			whitelist['mailExact'] = whitelist_dict['exactMatching']['mail']
			whitelist['mailRegex'] = whitelist_dict['regexMatching']['mail']
			whitelist['ipExact'] = whitelist_dict['exactMatching']['ip']
			whitelist['ipRegex'] = whitelist_dict['regexMatching']['ip']
			whitelist['domainExact'] = whitelist_dict['exactMatching']['domain']
			whitelist['domainRegex'] = whitelist_dict['regexMatching']['domain']
			whitelist['urlExact'] = whitelist_dict['exactMatching']['url']
			whitelist['urlRegex'] = whitelist_dict['regexMatching']['url']
			whitelist['filenameExact'] = whitelist_dict['exactMatching']['filename']
			whitelist['filenameRegex'] = whitelist_dict['regexMatching']['filename']
			whitelist['filetypeExact'] = whitelist_dict['exactMatching']['filetype']
			whitelist['hashExact'] = whitelist_dict['exactMatching']['hash']
			# The domains in the last three lists are used to create three lists of regular expressions that serve to whitelist subdomains, URLs and email addresses based on those domains
			whitelist['regexDomainsInSubdomains'] = [r'^(.+\.|){0}$'.format(domain.replace(r'.', r'\.')) for domain in whitelist_dict['domainsInSubdomains']]
			whitelist['regexDomainsInURLs'] = [r'^(http|https):\/\/([^\/]+\.|){0}(\/.*|\?.*|\#.*|)$'.format(domain.replace(r'.', r'\.')) for domain in whitelist_dict['domainsInURLs']]
			whitelist['regexDomainsInEmails'] = [r'^.+@(.+\.|){0}$'.format(domain.replace(r'.', r'\.')) for domain in whitelist_dict['domainsInEmails']]
	except Exception:
		log.error("Error while trying to open the file 'whitelist.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'whitelist.json'")

		return

	# Connect to IMAP server
	try:
		connection = connect_to_imap_server(wsl)
	except Exception:
		log.error("Error while trying to connect to IMAP server: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to connect to IMAP server")

		return

	proc_filters("email", wsl)
	proc_filters("domain", wsl)

	# Call the obtain_eml function
	try:
		internal_msg, external_from_field = obtain_eml(connection, mail_uid, wsl)
	except Exception:
		log.error("Error while trying to obtain the internal eml file: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to obtain the internal eml file")

		return

	# Call the parse_eml function
	try:
		subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, auth_results = parse_eml(internal_msg, wsl)
	except Exception:
		log.error("Error while trying to parse the internal eml file: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to parse the internal eml file")

		return

	# Call the create_case function
	try:
		new_case = create_case(subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, wsl)
	except Exception:
		log.error("Error while trying to create the case: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to create the case")

		return

	return new_case, external_from_field, subject_field, skip_cortex, auth_results