<?php
/**
 * WHMCS Login Fix Script - WHMCS 8.13.0
 * D1337 SOVEREIGN LABS
 */

define('DB_HOST', 'localhost');
define('DB_USER', 'scalacom_bcmashaire');
define('DB_PASS', 'r?1%?,7Et^.&');
define('DB_NAME', 'scalacom_clients');

$new_password = 'Kontolodon123@';

?>
<!DOCTYPE html>
<html>
<head>
    <title>WHMCS Login Fix - WHMCS 8.13.0</title>
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
    <h1>🔧 WHMCS Login Fix - Version 8.13.0</h1>

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
                
                // 5. Clear any password reset tokens
                $stmt = $conn->prepare("UPDATE tbladmins SET password_reset_key = NULL, password_reset_expiry = NULL WHERE id = ?");
                $stmt->bind_param("i", $admin_id);
                $stmt->execute();
                echo '<div class="success">✓ Password reset tokens cleared</div>';
                
                $conn->commit();
                
                // Get final admin details
                $result = $conn->query("SELECT username, email FROM tbladmins WHERE id = $admin_id");
                if ($result && $row = $result->fetch_assoc()) {
                    echo '<div class="success">';
                    echo '<h3>✅ FIXED! Login Credentials:</h3>';
                    echo '<strong>URL:</strong> https://web.caelumhosting.com/clients/admin/<br>';
                    echo '<strong>Username:</strong> <code>' . htmlspecialchars($row['username']) . '</code><br>';
                    echo '<strong>Password:</strong> <code>' . htmlspecialchars($new_pass) . '</code><br>';
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
                    
                    $login_url = 'https://web.caelumhosting.com/clients/admin/dologin.php';
                    
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
        <input type="password" name="new_password" value="D1337Admin2026!" required>
        
        <br><br>
        <button type="submit">🔧 Step 2: Fix Everything & Reset Password</button>
    </form>
    
    <h3>🔐 Test Login:</h3>
    <form method="POST">
        <input type="hidden" name="action" value="check_login">
        
        <label>Username:</label>
        <input type="text" name="test_username" value="admin" required>
        
        <label>Password:</label>
        <input type="password" name="test_password" value="D1337Admin2026!" required>
        
        <br><br>
        <button type="submit">🔐 Step 3: Test Login Credentials</button>
    </form>
    
    <div class="warning" style="margin-top: 20px;">
        <strong>⚠️ Instructions:</strong><br>
        1. Click "Diagnose" first to see what's wrong<br>
        2. Click "Fix Everything" to reset password + enable account + disable 2FA<br>
        3. Click "Test Login" to verify password works<br>
        4. Then try logging in at WHMCS admin panel<br>
        5. Delete this file after success!
    </div>
</div>
</body>
</html>
