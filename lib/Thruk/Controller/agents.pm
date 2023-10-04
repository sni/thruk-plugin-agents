package Thruk::Controller::agents;

use warnings;
use strict;
use Cpanel::JSON::XS qw/decode_json/;

use Thruk::Action::AddDefaults ();
use Thruk::Timer qw/timing_breakpoint/;
use Thruk::Utils::Agents ();
use Thruk::Utils::Auth ();
use Thruk::Utils::Conf ();
use Thruk::Utils::Log qw/:all/;

=head1 NAME

Thruk::Controller::agents - Thruk Controller

=head1 DESCRIPTION

Thruk Controller.

=head1 METHODS

=cut

##########################################################

=head2 index

=cut
sub index {
    my($c) = @_;
    &timing_breakpoint('index start');

    # Safe Defaults required for changing backends
    return unless Thruk::Action::AddDefaults::add_cached_defaults($c);

    return $c->detach('/error/index/8') unless $c->check_user_roles("admin");

    $c->stash->{title}         = 'Agents';
    $c->stash->{page}          = 'agents';
    $c->stash->{template}      = 'agents.tt';

    $c->stash->{build_agent}   = \&Thruk::Utils::Agents::build_agent;

    $c->stash->{no_tt_trim}    = 1;
    $c->stash->{'plugin_name'} = Thruk::Utils::get_plugin_name(__FILE__, __PACKAGE__);

    my $config_backends = Thruk::Utils::Conf::set_backends_with_obj_config($c);
    $c->stash->{config_backends}       = $config_backends;
    $c->stash->{has_multiple_backends} = scalar keys %{$config_backends} > 1 ? 1 : 0;

    # always convert backend name to key
    my $backend  = $c->req->parameters->{'backend'};
    if($backend) {
        my $peer = $c->db->get_peer_by_key($backend);
        if($peer) {
            $c->req->parameters->{'backend'} = $peer->{'key'};
            $backend = $peer->{'key'};
        }
    }

    my $action = $c->req->parameters->{'action'} || 'show';
    $c->stash->{action} = $action;

    Thruk::Utils::ssi_include($c);

       if($action eq 'show')   { return _process_show($c); }
    elsif($action eq 'new')    { return _process_new($c); }
    elsif($action eq 'edit')   { return _process_edit($c); }
    elsif($action eq 'scan')   { return _process_scan($c); }
    elsif($action eq 'save')   { return _process_save($c); }
    elsif($action eq 'remove') { return _process_remove($c); }
    elsif($action eq 'json')   { return _process_json($c); }

    return $c->detach_error({ msg  => 'no such action', code => 400 });
}

##########################################################
sub _process_show {
    my($c) = @_;

    my $hosts = $c->db->get_hosts(filter => [ Thruk::Utils::Auth::get_auth_filter( $c, 'hosts' ),
                                              'custom_variables' => { '~' => 'AGENT .+' },
                                            ],
                                 );
    $c->stash->{data} = $hosts;

    return;
}

##########################################################
sub _process_new {
    my($c) = @_;

    my $agent = {
        'type'     => _default_agent_type($c),
        'hostname' => $c->req->parameters->{'hostname'} // 'new',
        'section'  => $c->req->parameters->{'section'}  // '',
        'ip'       => $c->req->parameters->{'ip'}       // '',
        'port'     => $c->req->parameters->{'port'}     // '',
        'password' => $c->req->parameters->{'password'} // '',
        'peer_key' => $c->req->parameters->{'backend'}  // '',
    };
    return _process_edit($c, $agent);
}

##########################################################
sub _process_edit {
    my($c, $agent) = @_;

    my $hostname = $c->req->parameters->{'hostname'};
    my $backend  = $c->req->parameters->{'backend'};

    my $hostobj;
    if(!$agent && $hostname) {
        return unless Thruk::Utils::Agents::set_object_model($c, $backend);
        my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
        if(!$objects || scalar @{$objects} == 0) {
            return _process_new($c);
        }
        $hostobj = $objects->[0];
        my $obj = $hostobj->{'conf'};
        $agent = {
            'type'     => _default_agent_type($c),
            'hostname' => $hostname,
            'ip'       => $obj->{'address'}         // '',
            'section'  => $obj->{'_AGENT_SECTION'}  // '',
            'port'     => $obj->{'_AGENT_PORT'}     // '',
            'password' => $obj->{'_AGENT_PASSWORD'} // '',
            'peer_key' => $backend,
        };
    }

    # extract checks
    my $checks = Thruk::Utils::Agents::get_agent_checks_for_host($c, $hostname, $hostobj, $hostobj ? undef : _default_agent_type($c));

    my $services = $c->db->get_services( filter => [ Thruk::Utils::Auth::get_auth_filter( $c, 'services' ), { host_name => $hostname }], backend => $backend );
    $services = Thruk::Base::array2hash($services, "description");

    $c->stash->{services}         = $services;
    $c->stash->{checks}           = $checks;
    $c->stash->{'no_auto_reload'} = 1;
    $c->stash->{template}         = 'agents_edit.tt';
    $c->stash->{agent}            = $agent;

    return;
}

##########################################################
sub _default_agent_type {
    my($c) = @_;
    my $types = Thruk::Utils::Agents::find_agent_module_names();
    return(lc($types->[0]));
}

##########################################################
sub _process_save {
    my($c) = @_;

    my $type      = lc($c->req->parameters->{'type'});
    my $hostname  = $c->req->parameters->{'hostname'};
    my $backend   = $c->req->parameters->{'backend'};
    my $section   = $c->req->parameters->{'section'};
    my $password  = $c->req->parameters->{'password'};
    my $port      = $c->req->parameters->{'port'};
    my $ip        = $c->req->parameters->{'ip'};

    if(!$hostname) {
        Thruk::Utils::set_message( $c, 'fail_message', "hostname is required");
        return _process_new($c);
    }

    if(!$backend) {
        Thruk::Utils::set_message( $c, 'fail_message', "backend is required");
        return _process_new($c);
    }

    if(Thruk::Base::check_for_nasty_filename($hostname)) {
        Thruk::Utils::set_message( $c, 'fail_message', "this hostname is not allowed");
        return _process_new($c);
    }

    if(Thruk::Base::check_for_nasty_filename($section)) {
        Thruk::Utils::set_message( $c, 'fail_message', "this section is not allowed");
        return _process_new($c);
    }

    # TODO: add extra logic if old_backend or old_hostname is set and different

    return unless Thruk::Utils::Agents::set_object_model($c, $backend);

    my $data = {
        hostname => $hostname,
        backend  => $backend,
        section  => $section,
        password => $password,
        port     => $port,
        ip       => $ip,
    };

    my $class   = Thruk::Utils::Agents::get_agent_class($type);
    my $agent   = $class->new();
    my $objects = $agent->get_config_objects($c, $data);
    for my $obj (@{$objects}) {
        $c->{'obj_db'}->update_object($obj, $obj->{'conf'}, "", 1);
    }

    if($c->{'obj_db'}->commit($c)) {
        $c->stash->{'obj_model_changed'} = 1;
    }
    Thruk::Utils::Conf::store_model_retention($c, $c->stash->{'param_backend'});

    Thruk::Utils::set_message( $c, 'success_message', "changes saved successfully");
    return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi?action=edit&hostname=".$hostname."&backend=".$backend);
}

##########################################################
sub _process_remove {
    my($c) = @_;

    my $hostname  = $c->req->parameters->{'hostname'};
    my $backend   = $c->req->parameters->{'backend'};

    if(!$hostname) {
        Thruk::Utils::set_message( $c, 'fail_message', "hostname is required");
        return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi");
    }

    if(!$backend) {
        Thruk::Utils::set_message( $c, 'fail_message', "backend is required");
        return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi");
    }

    return unless Thruk::Utils::Agents::set_object_model($c, $backend);

    my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
    for my $obj (@{$objects}) {
        my $services = $c->{'obj_db'}->get_services_for_host($obj);
        if($services && $services->{'host'}) {
            my $removed = 0;
            for my $name (sort keys %{$services->{'host'}}) {
                my $svc = $services->{'host'}->{$name};
                next unless $svc->{'conf'}->{'_AGENT_AUTO_CHECK'};
                $c->{'obj_db'}->delete_object($svc);
                $removed++;
            }
            # TODO: show "reload" button
            if($removed < scalar keys %{$services->{'host'}}) {
                Thruk::Utils::set_message( $c, 'fail_message', "cannot remove host $hostname, there are still services connected to this host.");
                return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi");
            }
        }

        # only remove host if it has been created here
        if($obj->{'conf'}->{'_AGENT'}) {
            $c->{'obj_db'}->delete_object($obj);
        }
    }

    if($c->{'obj_db'}->commit($c)) {
        $c->stash->{'obj_model_changed'} = 1;
    }
    Thruk::Utils::Conf::store_model_retention($c, $c->stash->{'param_backend'});

    Thruk::Utils::set_message( $c, 'success_message', "host $hostname removed successfully");
    return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi");
}

##########################################################
sub _process_scan {
    my($c) = @_;

    return unless Thruk::Utils::check_csrf($c);

    my $agenttype = $c->req->parameters->{'type'};
    my $hostname  = $c->req->parameters->{'hostname'};
    my $address   = $c->req->parameters->{'ip'};
    my $password  = $c->req->parameters->{'password'};
    my $backend   = $c->req->parameters->{'backend'};
    my $port      = $c->req->parameters->{'port'} || '8443';

    return unless Thruk::Utils::Agents::set_object_model($c, $backend);

    # use existing password
    if(!$password) {
        my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
        if(!$objects || scalar @{$objects} == 0) {
            die("cannot find host");
        }
        my $obj = $objects->[0]->{'conf'};
        $password = $obj->{'_AGENT_PASSWORD'};
    }

    my $class = Thruk::Utils::Agents::get_agent_class($agenttype);
    my $agent = $class->new({});
    my $data;
    eval {
        $data = $agent->get_inventory($c, $address, $hostname, $password, $port);
    };
    my $err = $@;
    if($err) {
        $err = Thruk::Base::trim_whitespace($err);
        Thruk::Utils::set_message( $c, 'fail_message', "failed to scan agent: ".$err );
    } else {
        # save scan results
        Thruk::Utils::IO::mkdir_r($c->config->{'tmp_path'}.'/agents/hosts');
        Thruk::Utils::IO::json_lock_store($c->config->{'tmp_path'}.'/agents/hosts/'.$hostname.'.json', $data, { pretty => 1 });
    }

    return $c->render(json => { ok => 1 });
}

##########################################################
sub _process_json {
    my($c) = @_;

    my $json = [];
    my $type = $c->req->parameters->{'type'} // '';
    if($type eq 'section') {
        my $hosts = $c->db->get_hosts(filter => [ Thruk::Utils::Auth::get_auth_filter( $c, 'hosts' ),
                                                'custom_variables' => { '~' => 'AGENT .+' },
                                                ],
                                    );
        my $sections = {};
        for my $hst (@{$hosts}) {
            my $vars  = Thruk::Utils::get_custom_vars($c, $hst);
            $sections->{$vars->{'_AGENT_SECTION'}} = 1 if $vars->{'_AGENT_SECTION'};
        }
        push @{$json}, { 'name' => "sections", 'data' => [sort keys %{$sections} ] };
    }
    elsif($type eq 'site') {
        my $config_backends = Thruk::Utils::Conf::set_backends_with_obj_config($c);
        my $data = [];
        for my $key (sort keys %{$config_backends}) {
            my $peer = $c->db->get_peer_by_key($key);
            if($peer && $peer->{'name'}) {
                push @{$data}, $peer->{'name'};
            }
            @{$data} = sort @{$data};
        }
        push @{$json}, { 'name' => "sites", 'data' => $data };
    }

    return $c->render(json => $json);
}

##########################################################

1;
