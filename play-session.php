<?php

function usePlaySessionHandler ($cookie_name, $secret, $expire = 0, $cookie_path = '/') {
  ini_set('session.use_cookies', 0);
  
  $unserializeSession = function ( $data ) {
    if (strlen( $data) == 0) return array();
    
    // match all the session keys and offsets
    preg_match_all('/(^|;|\})([a-zA-Z0-9_\-]+)\|/i', $data, $matchesarray, PREG_OFFSET_CAPTURE);

    $returnArray = array();

    $lastOffset = null;
    $currentKey = '';
    foreach ( $matchesarray[2] as $value ) {
      $offset = $value[1];
      if(!is_null( $lastOffset)) {
        $valueText = substr($data, $lastOffset, $offset - $lastOffset );
        $returnArray[$currentKey] = unserialize($valueText);
      }
      $currentKey = $value[0];

      $lastOffset = $offset + strlen( $currentKey )+1;
    }

    $valueText = substr($data, $lastOffset );
    $returnArray[$currentKey] = unserialize($valueText);
    
    return $returnArray;
  };
  

  $serializeSession = function ( array $array ) {
    $raw = '' ;
    $line = 0 ;
    $keys = array_keys( $array ) ;
    foreach( $keys as $key ) {
      $value = $array[ $key ] ;
      $line ++ ;
      
      $raw .= $key .'|' ;
      
      if( is_array( $value ) && isset( $value['huge_recursion_blocker_we_hope'] )) {
        $raw .= 'R:'. $value['huge_recursion_blocker_we_hope'] . ';' ;
      } else {
        $raw .= serialize( $value ) ;
      }
      $array[$key] = Array( 'huge_recursion_blocker_we_hope' => $line ) ;
    }
    return $raw ;  
  };

  $stringify = function (array $data) {
    $s = '';
    foreach ($data as $key=>$value) {
      $s .= "\000" . $key . ':' . $value . "\000";
    }
    return $s;
  };
  $sign = function ($session_string) use (&$secret) {
    return hash_hmac('sha1', urlencode($session_string), $secret);
  };
  $signData = function (array $data) use (&$stringify, &$sign) {
    $s = $stringify($data);
    $sig = $sign($s);
    return $sig . '-' . $s;
  };

  $session_data = array();
  $data = '';

  session_set_save_handler(  
    // open
    function ($save_path, $name) {
      return true;
    }, 

    // close
    function () use (&$session_data, &$signData, &$unserializeSession, &$cookie_name, &$data, &$expire, $cookie_path) {
      if ($data == '') {
        setcookie($cookie_name, '');
      } else {
        $session_data = $unserializeSession($data);
        setcookie($cookie_name, $signData($session_data), $expire, $cookie_path);
      }
      return false;
    },

    // read
    function ($id) use (&$session_data, &$sign, &$cookie_name, &$serializeSession) {
      if (isset($_COOKIE[$cookie_name])) {
        $data = $_COOKIE[$cookie_name];
        $d2 = explode('-', $data);
        $signature = array_shift($d2);
        $session_string = implode('-', $d2);

        // verify signature
        if ($sign($session_string) != $signature) return false;
                
        $tmp = explode("\000\000", $session_string);
        $data = array();
        foreach ($tmp as $v) {
          $v = str_replace("\000", "", $v);
          $tmp2 = explode(":", $v);
          $key = array_shift($tmp2);
          $value = implode(':', $tmp2);
          $data[$key] = $value;
        }
        
        // verify timestamp
        if (!isset($data['ts']) || intval($data['ts'], 10) < (time() - 60*60*24*2)) return false;
        
        $session_data = $data;
      }
      
      return $serializeSession($session_data);
    },

    // write
    function ($id, $d) use (&$data) {
      $data = $d;
    },
    // destroy
    function () {},
    // gc 
    function () {}
  );
};

