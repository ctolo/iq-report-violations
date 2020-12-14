#!/usr/bin/python3
# ----------------------------------------------------------------------------
# Python Dependencies
import time
import datetime
import json
import argparse
import asyncio
import aiohttp

# ----------------------------------------------------------------------------
t0 = time.time()
iq_url, iq_session = "", ""
api_calls = 0

def getArguments():
    global iq_url, iq_session, iq_auth
    parser = argparse.ArgumentParser(description='Export Reporting Recommendations')
    parser.add_argument('-i', '--publicId', help='PublicId for the Application', required=True)
    parser.add_argument('-s', '--stage', help='Stage of the scan', default="build", required=False)
    parser.add_argument('-u', '--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a', '--auth', help='', default="admin:admin123", required=False)
    args = vars(parser.parse_args())
    iq_url = args["url"]
    creds = args["auth"].split(":")
    iq_session = aiohttp.ClientSession()
    iq_auth = aiohttp.BasicAuth(creds[0], creds[1])
    return args

async def main():
    args = getArguments()
    publicId = args["publicId"]
    stage = args["stage"]

    application = await get_application(publicId)
    applicationId = application["id"]
    reportId = await get_reportId(applicationId, stage)
    report = await get_policy_violations(publicId, reportId)
    raw = await get_raw_report(publicId, reportId)
    organizationName = await get_organizationName(application["organizationId"])

    report["reportTime"] = get_epoch(report["reportTime"])
    report["application"].update({"organizationName": organizationName})

    for component in raw["components"]:
        issues = {}
        if component["securityData"] is not None and component["securityData"]["securityIssues"] is not None:
            for issue in component["securityData"]["securityIssues"]:
                issues.update({issue["reference"]:{"severity":issue["severity"],"status":issue["status"]}})
            raw.update({component["hash"]: issues })

    for component in report['components']:
        clean_dict(component, ["componentIdentifier","pathnames"])
        for violations in component["violations"]:
            clean_dict(violations, ["constraints"])
            violation = await get_violation(violations["policyViolationId"]) 
            r = violation["constraintViolations"][0]["reasons"][0]
            violation["reason"] = r["reason"] if r["reference"] is None else r["reference"]["value"]
            violation.update({"severity": None, "status": None})
            if violation["hash"] in raw.keys():
                if violation["reason"] in raw[violation["hash"]].keys():
                    violation.update( raw[violation["hash"]][violation["reason"]] )

            clean_dict(violation, ["displayName","constraintViolations","threatLevel","filename","componentIdentifier","applicationPublicId","applicationName","organizationName","stageData","policyOwner"])
            violations.update(violation)

    await iq_session.close()

    with open("results.json", "w+") as file:
        file.write(json.dumps(report, indent=4))
    print("Json results saved to -> results.json")


    csv = []
    for component in report['components']:
        for violation in component["violations"]:
            csv.append({
                "Organization_Name": organizationName,
                "Application_Name": report["application"]["name"],
                "Application_ID": publicId,
                "Report_Type": stage,
                "Scan_Date": report["reportTime"],
                "Threat_Score": violation["policyThreatLevel"],
                "Policy": violation["policyName"],
                "Component_Name": component["displayName"],
                "Status": violation["status"],
            })

    with open("results.csv", "w+") as file:

        file.write(",".join(list(csv[0].keys()))+"\n")
        for c in csv:
            file.write(",".join( str(value) for value in c.values()  )+"\n")

    print("Json results saved to -> results.csv")

# -----------------------------------------------------------------------------
def clean_dict(dictionary, remove_list):
    for e in remove_list: 
        dictionary.pop(e, None)

async def handle_resp(resp, root=""):
    global api_calls
    api_calls += 1
    if resp.status != 200:
        print(await resp.text())
        return None
    node = await resp.json()
    if root in node:
        node = node[root]
    if node is None or len(node) == 0:
        return None
    return node

async def get_url(url, root=""):
    resp = await iq_session.get(url, auth=iq_auth)
    return await handle_resp(resp, root)

def get_epoch(epoch_ms):
    dt_ = datetime.datetime.fromtimestamp(epoch_ms/1000)
    return dt_.strftime("%Y-%m-%d %H:%M:%S")

async def get_organizationName(organizationId):
    url = f'{iq_url}/api/v2/organizations/{organizationId}'
    return await get_url(url, "name")

async def get_application(publicId):
    url = f'{iq_url}/api/v2/applications?publicId={publicId}'
    apps = await get_url(url, "applications")
    if apps is None:
        return None
    return apps[0]

async def get_reportId(applicationId, stageId):
    url = f"{iq_url}/api/v2/reports/applications/{applicationId}"
    reports = await get_url(url)
    for report in reports:
        if report["stage"] in stageId:
            return report["reportHtmlUrl"].split("/")[-1]

async def get_policy_violations(publicId, reportId):
    url = f'{iq_url}/api/v2/applications/{publicId}/reports/{reportId}/policy'
    return await get_url(url)

async def get_raw_report(publicId, reportId):
    url = f'{iq_url}/api/v2/applications/{publicId}/reports/{reportId}'
    return await get_url(url)

async def get_violation(policyViolationId):
    url = f'{iq_url}/api/v2/policyViolations/crossStage/{policyViolationId}'
    return await get_url(url)

if __name__ == "__main__":
    asyncio.run(main())
