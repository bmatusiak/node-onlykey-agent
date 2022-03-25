#!/usr/bin/env node

//  node cli.js > out.sh ; source out.sh ; rm out.sh
var argv = require('minimist')(process.argv.slice(2), { '--': true });

var remote, seed;

if (argv._.length == 1)
    seed = argv._[0];
    
if (argv.remote)
    remote = seed || argv.remote

if (remote) {

    if (!argv.sock_server) {
        if (argv['--'].length == 0) {
            ForkProcess(false, remote);

        }
        else {

            var cp = require('child_process');
            var cmd_line = Array.from(argv['--']);
            var cmd = cmd_line.shift();
            var args = cmd_line;
            console.log("remote", remote);

            var killServer = require("./nw-server.js")(remote, function(sock_info) {
                // childProc.send(sock_info);
                process.env.SSH_AUTH_SOCK = sock_info.sock;
                var cmd_proc = cp.spawn(cmd, args, { env: process.env, stdio: [process.stdin, process.stdout, process.stderr] });
                // console.log(cmd_proc,process)
                // process.stdin.pipe(cmd_proc.stdin)
                // cmd_proc.stdin.pipe(process.stdin)
                cmd_proc.on("exit", killServer);
            });

        }
    }
    else {
        console.log("sock_server")
        ForkProcess(true, remote);
    }
}

function ForkProcess(is_child, remote_hash) { // var is_child = ;
    var cp = require('child_process');

    var childProc;
    if (!is_child) {
        childProc = cp.fork(`${__filename}`, ["--sock_server", "--remote=" + remote_hash], {
            execArgv: [],
            detached: true
        });


        pidFile(childProc.pid);

        childProc.on('message', (m) => {

            if (m && m.sock && m.pid) {
                var ssh_agent_pid = m.pid;
                var ssh_auth_socket = m.sock;
                console.log("SSH_AUTH_SOCK=" + ssh_auth_socket + "; export SSH_AUTH_SOCK;");
                console.log("SSH_AGENT_PID=" + ssh_agent_pid + "; export SSH_AGENT_PID;");
                console.log("echo Agent pid " + ssh_agent_pid + "");
                process.exit(0);
            }
            // console.log('PARENT got message:', m);

        });

        // setTimeout(function() {
        //     childProc.send({ hello: 'world' });

        // }, 1000);

    }
    else {
        childProc = process;

        childProc.on('message', (m) => {
            // console.log('CHILD got message:', m);
        });


        setTimeout(function() {

            require("./nw-server.js")(remote_hash, function(sock_info) {
                childProc.send(sock_info);
            })
            // childProc.send({ foo: 'bar', baz: NaN, time: (new Date()).getTime() });

        }, 1000);



    }

    // console.log("pid", childProc.pid, process.argv[2]);
}


// setInterval(function() {

// }, 1000);


function pidFile(new_pid) {

    var cp = require('child_process');
    var fs = require("fs");

    var kill_exist = fs.existsSync("/usr/bin/kill");
    var pidFile = __dirname + "/process.pid";
    if (kill_exist) {
        var pid_id;

        if (fs.existsSync(pidFile)) {
            pid_id = fs.readFileSync(pidFile, "utf8");
            var kill_status = cp.spawnSync("/usr/bin/kill", ["-2", pid_id]).status;
            // console.log("cs.spawn", kill_status);
            fs.unlinkSync(pidFile);
            // process.exit();
            // console.log("killed", pid_id)
        }
        // else {

        pid_id = new_pid; //process.pid;
        fs.writeFileSync(pidFile, pid_id, "utf8")

        // console.log("spawned", pid_id)
        // process.exit();
        // }
    }

}
// startup(ready);