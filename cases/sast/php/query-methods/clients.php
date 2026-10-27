<?php
// Methods named query() that are not SQL: search clients, GraphQL clients and others. None may be
// reported as SQL injection.

function searchProducts(SearchClient $search)
{
    return $search->query($_GET['q']); // PHP-QRY-TN-001
}

function solr()
{
    $client = new SolrClient(['hostname' => 'localhost']);
    return $client->query($_GET['q']); // PHP-QRY-TN-002
}

function graphqlUser()
{
    $gql = new GraphQLClient('http://localhost:4000/graphql');
    return $gql->query('query { user(id: "' . $_GET['id'] . '") { name } }'); // PHP-QRY-TN-003
}

function graphqlTyped(\GraphQL\Client $client)
{
    return $client->query($_POST['query']); // PHP-QRY-TN-004
}

function elastic()
{
    $es = new ElasticClient(['localhost:9200']);
    return $es->query(['match' => ['title' => $_GET['q']]]); // PHP-QRY-TN-005
}

function httpQuery(\GuzzleHttp\Psr7\Uri $uri)
{
    return $uri->query($_GET['page']); // PHP-QRY-TN-006
}

function domQuery(DOMDocument $doc)
{
    $xp = new DOMXPath($doc);
    return $xp->query("//item[@id='" . $_GET['id'] . "']"); // PHP-QRY-XPATH-001
}

function factorySearch($container)
{
    $search = $container->get('search');
    return $search->query($_GET['q']); // PHP-QRY-TN-007
}
