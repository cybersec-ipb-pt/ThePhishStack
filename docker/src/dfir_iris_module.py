import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
contenttype = str("application/json")
status = {"Unknown": 0, "False positive": 1, "True positive with impact": 2, "Not applicable": 3, "True positive without impact": 4}
severity = {"Medium": 1, "Unspecified": 2, "Informational": 3, "Low": 4, "High": 5, "Critical": 6}

def get_templates(base_url, token, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/manage/case-templates/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        verify=verify_cert
    )

    return r

def upload_template(base_url, token, template, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/manage/case-templates/add",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=template,
        verify=verify_cert
    )

    return r

def get_classifications(base_url, token, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/manage/case-classifications/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        verify=verify_cert
    )

    return r

def create_case(base_url, token, payload, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/manage/cases/add",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

    return r

def update_case(base_url, token, case_id, payload, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/manage/cases/update/{case_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

    return r

def update_summary(base_url, token, payload, verify_cert):
    s = requests.Session()
    s.post(
        f"{base_url}/case/summary/update",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

def review_case(base_url, token, case_id, payload, verify_cert):
    s = requests.Session()
    s.post(
        f"{base_url}/case/review/update?cid={case_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

def close_case(base_url, token, case_id, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/manage/cases/close/{case_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        verify=verify_cert
    )

    return r

def get_tasks(base_url, token, payload, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/case/tasks/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

    return r

def update_task(base_url, token, task_id, payload, verify_cert):
    s = requests.Session()
    s.post(
        f"{base_url}/case/tasks/update/{task_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

def get_notes_group(base_url, token, payload, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/case/notes/directories/filter",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

    return r

def update_note(base_url, token, note_id, payload, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/case/notes/update/{note_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

    return r

def get_ioc_types(base_url, token, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/manage/ioc-types/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        verify=verify_cert
    )

    return r

def add_ioc(base_url, token, payload, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/case/ioc/add",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

    return r

def get_ioc_list(base_url, token, cid, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/case/ioc/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=cid,
        verify=verify_cert
    )

    return r

def get_ioc(base_url, token, iocid, cid, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/case/ioc/{iocid}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=cid,
        verify=verify_cert
    )

    return r

def update_ioc(base_url, token, iocid, payload, verify_cert):
    s = requests.Session()
    s.post(
        f"{base_url}/case/ioc/update/{iocid}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

def get_evidence_type(base_url, token, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/manage/evidence-types/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        verify=verify_cert
    )

    return r

def get_evidence_list(base_url, token, cid, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/case/evidences/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=cid,
        verify=verify_cert
    )

    return r

def update_evidence(base_url, token, evidence_id, cid, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/case/evidences/update/{evidence_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=cid,
        verify=verify_cert
    )

    return r

def get_datastore_tree(base_url, token, cid, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/datastore/list/tree",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=cid,
        verify=verify_cert
    )

    return r

def upload_file(base_url, token, parent_id, cid, payload, file, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/datastore/file/add/{parent_id}?cid={cid}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/javascript, */*; q=0.01"
        },
        data=payload,
        files=file,
        verify=verify_cert
    )

    return r

def get_module_list(base_url, token, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/manage/modules/list",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        verify=verify_cert
    )

    return r.json()["data"]

def get_dim_task_status(base_url, token, verify_cert):
    s = requests.Session()
    r = s.get(
        f"{base_url}/dim/tasks/list/1",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        verify=verify_cert
    )

    if r.status_code != 200 or not (data := r.json().get('data')):
        return None

    return data[0]

def call_module(base_url, token, payload, verify_cert):
    s = requests.Session()
    r = s.post(
        f"{base_url}/dim/hooks/call",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": contenttype
        },
        data=payload,
        verify=verify_cert
    )

    return r