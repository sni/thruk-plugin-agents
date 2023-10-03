use warnings;
use strict;
use Test::More;
use Cpanel::JSON::XS qw/decode_json/;

use Thruk::Config 'noautoload';

BEGIN {
    plan skip_all => 'backends required' if(!-s 'thruk_local.conf' and !defined $ENV{'PLACK_TEST_EXTERNALSERVER_URI'});
    plan tests => 55;
}

BEGIN {
    use lib('t');
    require TestUtils;
    import TestUtils;
}

SKIP: {
    skip 'external tests', 1 if defined $ENV{'PLACK_TEST_EXTERNALSERVER_URI'};

    use_ok 'Thruk::Controller::agents';
};

#################################################
# normal pages
my $pages = [
    { url => '/thruk/cgi-bin/agents.cgi', like => ['Agents', 'Items Displayed'] },
    { url => '/thruk/cgi-bin/agents.cgi?action=new', like => ['Add Agent', 'Save Changes'] },
];

for my $page (@{$pages}) {
    TestUtils::test_page(%{$page});
}

#################################################
# json pages
$pages = [
    { url => '/thruk/cgi-bin/agents.cgi?action=json&type=section', post => { }, type => 'array', notempty => 1 },
    { url => '/thruk/cgi-bin/agents.cgi?action=json&type=site',    post => { }, type => 'array', notempty => 1 },
    { url => '/thruk/cgi-bin/agents.cgi?action=scan', post => {
        hostname => 'localhost',
        type     => 'snclient',
        password => 'test',
        backend  => 'http',
    }, type => 'hash', notempty => 1 },
];

for my $url (@{$pages}) {
    _test_json_page($url);
}

#################################################
sub _test_json_page {
    my($url) = @_;
    if(!ref $url) {
        $url = { url => $url };
    }
    $url->{'post'}         = {} unless $url->{'post'};
    $url->{'post'}         = undef if($url->{'method'} && lc($url->{'method'}) eq 'get');
    $url->{'content_type'} = 'application/json; charset=utf-8' unless $url->{'content_type'};

    my $page = TestUtils::test_page(%{$url});
    my $data;
    eval {
        $data = decode_json($page->{'content'});
    };
    is($@, '', "json decode is fine for: ".$url->{'url'});

    if($url->{'type'} eq 'hash') {
        is(ref $data, 'HASH', "json result is a hash: ".$url->{'url'});
        ok(scalar keys %{$data} > 0, "json result has content: ".$url->{'url'}) if $url->{'notempty'};
    }
    else {
        is(ref $data, 'ARRAY', "json result is an array: ".$url->{'url'});
        ok(scalar @{$data} > 0, "json result has content: ".$url->{'url'}) if $url->{'notempty'};
    }

    return($data);
}
