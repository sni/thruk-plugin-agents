package Thruk::Controller::agents;

use warnings;
use strict;
use Carp;
use Cpanel::JSON::XS qw/decode_json/;

use Monitoring::Config::Object ();
use Thruk::Action::AddDefaults ();
use Thruk::Controller::conf ();
use Thruk::Timer qw/timing_breakpoint/;
use Thruk::Utils::Agents ();
use Thruk::Utils::Auth ();
use Thruk::Utils::Conf ();
use Thruk::Utils::External ();
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

    my $hosts = $c->db->get_hosts(filter => [ Thruk::Utils::Auth::get_auth_filter( $c, 'hosts' ), 'custom_variables' => 'AGENT snclient']);
    $c->stash->{data} = $hosts;

    return;
}

##########################################################
sub _process_new {
    my($c) = @_;

    my $agent = {
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
        return unless _set_object_model($c, $backend);
        my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
        if(!$objects || scalar @{$objects} == 0) {
            return _process_new($c);
        }
        $hostobj = $objects->[0];
        my $obj = $hostobj->{'conf'};
        $agent = {
            'hostname' => $hostname,
            'ip'       => $obj->{'address'}         // '',
            'section'  => $obj->{'_AGENT_SECTION'}  // '',
            'port'     => $obj->{'_AGENT_PORT'}     // '',
            'password' => $obj->{'_AGENT_PASSWORD'} // '',
            'peer_key' => $backend,
        };
    }

    # extract checks
    my $checks = Thruk::Utils::Agents::get_agent_checks_for_host($c, $hostname, $hostobj);

    $c->stash->{checks}           = $checks;
    $c->stash->{'no_auto_reload'} = 1;
    $c->stash->{template}         = 'agents_edit.tt';
    $c->stash->{agent}            = $agent;

    return;
}

##########################################################
sub _process_save {
    my($c) = @_;

    my $hostname  = $c->req->parameters->{'hostname'};
    my $backend   = $c->req->parameters->{'backend'};
    my $section   = $c->req->parameters->{'section'}  // '';
    my $password  = $c->req->parameters->{'password'} // '';
    my $port      = $c->req->parameters->{'port'}     || '8443';
    my $ip        = $c->req->parameters->{'ip'}       // '';

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

    return unless _set_object_model($c, $backend);

    my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
    my $obj;
    if(!$objects || scalar @{$objects} == 0) {
        # create new one
        $obj = Monitoring::Config::Object->new( type     => 'host',
                                                   coretype => $c->{'obj_db'}->{'coretype'},
                                                );
        my $filename = $section ? sprintf('agents/%s/%s.cfg', $section, $hostname) : sprintf('agents/%s.cfg', $hostname);
        my $file = Thruk::Controller::conf::get_context_file($c, $obj, $filename);
        die("creating file failed") unless $file;
        $obj->set_file($file);
        $obj->set_uniq_id($c->{'obj_db'});
        $obj->{'conf'}->{'host_name'} = $hostname;
        $obj->{'conf'}->{'alias'}     = $hostname;
        $obj->{'conf'}->{'use'}       = "generic-host";
        $obj->{'conf'}->{'address'}   = $ip || $hostname;
    } else {
        $obj = $objects->[0];
    }

    # TODO: set icon image
    # TODO: add action menu
    my $data = $obj->{'conf'} // {};
    $data->{'_AGENT'}          = 'snclient';
    $data->{'_AGENT_PASSWORD'} = $password if($password ne ''); # only if changed
    $data->{'_AGENT_SECTION'}  = $section;
    $data->{'_AGENT_PORT'}     = $port;

    if(!$c->{'obj_db'}->update_object($obj, $data, "", 1)) {
        Thruk::Utils::set_message( $c, 'fail_message', "failed to save changes.");
        return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi?action=edit&hostname=".$hostname."&backend=".$backend);
    }

    # save services
    my $checks = Thruk::Utils::Agents::get_services_checks($c, $hostname, $obj);
    my $checks_hash = Thruk::Base::array2hash($checks, "id");
    for my $id (sort keys %{$checks_hash}) {
        my $type = $c->req->parameters->{'check.'.$id};
        my $chk  = $checks_hash->{$id};
        next unless $type && $type eq 'on';
        my $svc = $chk->{'_svc'};
        if(!$svc) {
            # create new one
            $svc = Monitoring::Config::Object->new( type     => 'service',
                                                    coretype => $c->{'obj_db'}->{'coretype'},
                                                    );
            my $filename = $section ? sprintf('agents/%s/%s.cfg', $section, $hostname) : sprintf('agents/%s.cfg', $hostname);
            my $file = Thruk::Controller::conf::get_context_file($c, $svc, $filename);
            die("creating file failed") unless $file;
            $svc->set_file($file);
            $svc->set_uniq_id($c->{'obj_db'});
        }

        # TODO: ARGS should be configurable somehow
        my $command = sprintf("check_snclient!-k -p '%s' -u 'https://%s:%s' %s",
                '$_HOSTAGENT_PASSWORD$',
                '$HOSTADDRESS$',
                '$_HOSTAGENT_PORT$',
                $chk->{'check'},
        );
        my $interval = 1;
        if($chk->{'check'} eq 'inventory') {
            $command  = sprintf("check_thruk_agents!agents check inventory '%s'", $hostname);
            $interval = 60;
        }
        if($chk->{'args'}) {
            for my $arg (sort keys %{$chk->{'args'}}) {
                $command .= sprintf(" %s='%s'", $arg, $chk->{'args'}->{$arg});
            }
        }

        confess("no name") unless $chk->{'name'};

        $svc->{'conf'} = {
            'host_name'           => $hostname,
            'service_description' => $chk->{'name'},
            'use'                 => 'generic-service',
            'check_interval'      => $interval,
            'check_command'       => $command,
            '_AGENT_AUTO_CHECK'   => $chk->{'id'},
        };
        $svc->{'conf'}->{'parents'} = $chk->{'parent'} if $chk->{'parent'};

        $c->{'obj_db'}->update_object($svc, $svc->{'conf'}, "", 1);
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

    return unless _set_object_model($c, $backend);

    my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
    for my $obj (@{$objects}) {
        my $services = $c->{'obj_db'}->get_services_for_host($obj);
        if($services && $services->{'host'}) {
            my $removed = 0;
            for my $name (sort keys %{$services->{'host'}}) {
                my $svc = $services->{$name};
                next unless $svc->{'conf'}->{'_AGENT_AUTO_CHECK'};
                $c->{'obj_db'}->delete_object($svc);
                $removed++;
            }
            # TODO: does not work?
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

    my $hostname = $c->req->parameters->{'hostname'};
    my $address  = $c->req->parameters->{'ip'};
    my $password = $c->req->parameters->{'password'};
    my $backend  = $c->req->parameters->{'backend'};
    my $port     = $c->req->parameters->{'port'} || '8443';

    return unless _set_object_model($c, $backend);

    # use existing password
    if(!$password) {
        my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
        if(!$objects || scalar @{$objects} == 0) {
            die("cannot find host");
        }
        my $obj = $objects->[0]->{'conf'};
        $password = $obj->{'_AGENT_PASSWORD'};
    }

    my $data;
    eval {
        $data = _get_inventory($c, $address, $hostname, $password, $port);
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

    return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi?action=edit&hostname=".$hostname."&backend=".$backend);
}

##########################################################
sub _process_json {
    my($c) = @_;

    my $json = [];
    my $type = $c->req->parameters->{'type'} // '';
    if($type eq 'section') {
        # TODO: ...
        push @{$json}, { 'name' => "sections", 'data' => [] };
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
sub _get_inventory {
    my($c, $address, $hostname, $password, $port) = @_;

    my $command  = "check_snclient";
    # TODO: make -k and such an option
    my $args     = sprintf("-k -p '%s' -r -u 'https://%s:%d/api/v1/inventory'",
        $password,
        ($address || $hostname),
        $port,
    );

    _check_for_check_commands($c);

    my $output = $c->{'obj_db'}->get_plugin_preview($c,
                                        $command,
                                        $args,
                                        $hostname,
                                        '',
                                    );
    if($output =~ m/^\{/mx) {
        my $data;
        eval {
            $data = decode_json($output);
        };
        my $err = $@;
        if($err) {
            die($err);
        }
        return $data;
    }
    die($output);
}

##########################################################
sub _check_for_check_commands {
    my($c) = @_;

    my $changed = 0;
    $changed++ unless _ensure_command_exists($c, "check_snclient", {
        command_name => 'check_snclient',
        command_line => '$USER1$/check_nsc_web $ARG1$',
    });
    $changed++ unless _ensure_command_exists($c, "check_thruk_agents", {
        command_name => 'check_thruk_agents',
        command_line => '$USER4$/bin/thruk $ARG1$',
    });

    if($changed) {
        if($c->{'obj_db'}->commit($c)) {
            $c->stash->{'obj_model_changed'} = 1;
        }
        Thruk::Utils::Conf::store_model_retention($c, $c->stash->{'param_backend'});
    }

    return;
}

##########################################################
sub _ensure_command_exists {
    my($c, $name, $data) = @_;

    my $objects = $c->{'obj_db'}->get_objects_by_name('command', $name);
    if($objects && scalar @{$objects} > 0) {
        return 1;
    }

    my $obj = Monitoring::Config::Object->new( type     => 'command',
                                               coretype => $c->{'obj_db'}->{'coretype'},
                                            );
    my $file = Thruk::Controller::conf::get_context_file($c, $obj, 'agents/commands.cfg');
    die("creating file failed") unless $file;
    $obj->set_file($file);
    $obj->set_uniq_id($c->{'obj_db'});
    $c->{'obj_db'}->update_object($obj, $data, "", 1);
    return;
}

##########################################################
# returns 1 on success, 0 on redirects. Dies otherwise.
sub _set_object_model {
    my($c, $peer_key, $retries) = @_;
    $retries = 0 unless defined $retries;

    $c->stash->{'param_backend'} = $peer_key;
    delete $c->{'obj_db'};
    my $rc = Thruk::Utils::Conf::set_object_model($c, undef, $peer_key);
    if($rc == 0 && $c->stash->{set_object_model_err}) {
        if($retries < 3 && $c->stash->{"model_job"}) {
            my $is_running = Thruk::Utils::External::wait_for_job($c, $c->stash->{"model_job"}, 30);
            if(!$is_running) {
                return(_set_object_model($c, $peer_key, $retries+1));
            }
        }
        die(sprintf("backend %s returned error: %s", $peer_key, $c->stash->{set_object_model_err}));
    }
    delete $c->req->parameters->{'refreshdata'};
    if(!$c->{'obj_db'}) {
        die(sprintf("backend %s has no config tool settings", $peer_key));
    }
    # make sure we did not fallback on some default backend
    if($c->stash->{'param_backend'} ne $peer_key) {
        die(sprintf("backend %s has no config tool settings", $peer_key));
    }
    if($c->{'obj_db'}->{'errors'} && scalar @{$c->{'obj_db'}->{'errors'}} > 0) {
        die(sprintf("failed to initialize objects of peer %s", $peer_key));
    }
    return 1;
}

##########################################################

1;
