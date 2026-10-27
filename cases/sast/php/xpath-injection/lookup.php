<?php
// XPath injection cases for TG-TAINT-PHP-XPATH-INJECTION. These must be reported as XPath
// injection (CWE-643), not SQL injection.

function userByName(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    return $xp->query("//user[name='" . $_GET['name'] . "']"); // PHP-XPATH-TP-001
}

function countCategory(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    return $xp->evaluate("count(//item[@cat='" . $_POST['cat'] . "'])"); // PHP-XPATH-TP-002
}

function bookByTitle(DOMXPath $x)
{
    return $x->query("//book[title='" . $_REQUEST['title'] . "']"); // PHP-XPATH-TP-003
}

function simpleXmlById($xml)
{
    $sx = new SimpleXMLElement($xml);
    return $sx->xpath("//account[@id='" . $_GET['id'] . "']"); // PHP-XPATH-TP-004
}

function fromString($xml)
{
    $sx = simplexml_load_string($xml);
    return $sx->xpath("//pref[@key='" . $_COOKIE['pref'] . "']"); // PHP-XPATH-TP-005
}

function fromFile()
{
    $sx = simplexml_load_file('/srv/app/catalog.xml');
    return $sx->xpath("//product[sku='" . $_GET['sku'] . "']"); // PHP-XPATH-TP-006
}

function viaVariable(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    $expr = "//link[@href='" . $_GET['href'] . "']"; // PHP-XPATH-TP-007
    return $xp->query($expr); // PHP-XPATH-TP-007
}

function interpolated(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    return $xp->query("//order[@ref='{$_POST['ref']}']"); // PHP-XPATH-TP-008
}

function nullableParam(?DOMXPath $x)
{
    return $x->evaluate("//node[@n='" . $_GET['n'] . "']"); // PHP-XPATH-TP-009
}

function qualified(DOMDocument $doc)
{
    $xp = new \DOMXPath($doc);
    return $xp->query("//member[@login='" . $_GET['login'] . "']"); // PHP-XPATH-TP-010
}

function activeUsers(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    return $xp->query("//user[@active='1']"); // PHP-XPATH-TN-001
}

function constantField(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    $field = 'email';
    return $xp->query("//user/" . $field); // PHP-XPATH-TN-002
}

function simpleStatic($xml)
{
    $sx = new SimpleXMLElement($xml);
    return $sx->xpath("//product[@featured='yes']"); // PHP-XPATH-TN-003
}

function numericId(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    return $xp->query("//user[@id=" . (int) $_GET['id'] . "]"); // PHP-XPATH-TN-004
}
