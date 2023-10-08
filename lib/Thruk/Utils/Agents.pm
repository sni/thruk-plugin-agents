package Thruk::Utils::Agents;

use warnings;
use strict;
use Carp qw/confess/;
use Cpanel::JSON::XS qw/decode_json/;

use Monitoring::Config::Object ();
use Thruk::Controller::conf ();
use Thruk::Timer qw/timing_breakpoint/;
use Thruk::Utils ();
use Thruk::Utils::Conf ();
use Thruk::Utils::External ();
use Thruk::Utils::Log qw/:all/;

=head1 NAME

Thruk::Utils::Agents - Utils for agents

=head1 METHODS

=cut

##########################################################

=head2 get_agent_checks_for_host

    get_agent_checks_for_host($c, $hostname, $hostobj, [$agenttype])

returns list of checks for this host grouped by type (new, exists, obsolete, disabled) along with the total number of checks.

=cut
sub get_agent_checks_for_host {
    my($c, $hostname, $hostobj, $agenttype) = @_;
    # extract checks and group by type
    my $flat   = get_services_checks($c, $hostname, $hostobj, $agenttype);
    my $checks = Thruk::Base::array_group_by($flat, "exists");
    for my $key (qw/new exists obsolete disabled/) {
        $checks->{$key} = [] unless defined $checks->{$key};
    }

    return($checks, scalar @{$flat});
}

##########################################################

=head2 update_inventory

    update_inventory($c, $hostname, [$hostobj])

returns $data and $err

=cut
sub update_inventory {
    my($c, $hostname, $hostobj) = @_;

    if(!$hostobj) {
        my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
        if(!$objects || scalar @{$objects} == 0) {
            $hostobj = $objects->[0];
        }
    }
    die("hostobj required") unless $hostobj;

    my $hostname  = $hostobj->{'conf'}->{'name'};
    my $address   = $hostobj->{'conf'}->{'address'};
    my $type      = $hostobj->{'conf'}->{'_AGENT'};
    my $password  = $hostobj->{'conf'}->{'_AGENT_PASSWORD'} || $c->config->{'Thruk::Agents'}->{lc($type)}->{'default_password'};
    my $port      = $hostobj->{'conf'}->{'_AGENT_PORT'};

    my $class = Thruk::Utils::Agents::get_agent_class($type);
    my $agent = $class->new({});
    my $data;
    eval {
        $data = $agent->get_inventory($c, $address, $hostname, $password, $port);
    };
    my $err = $@;
    if($err) {
        return(undef, $err);
    } else {
        if($data) {
            # save scan results
            Thruk::Utils::IO::mkdir_r($c->config->{'tmp_path'}.'/agents/hosts');
            Thruk::Utils::IO::json_lock_store($c->config->{'tmp_path'}.'/agents/hosts/'.$hostname.'.json', $data, { pretty => 1 });
        }
    }

    return($data, undef);
}

##########################################################

=head2 get_services_checks

    get_services_checks($c, $hostname, $hostobj, $agenttype)

returns list of checks as flat list.

=cut
sub get_services_checks {
    my($c, $hostname, $hostobj, $agenttype) = @_;
    my $checks   = [];
    return($checks) unless $hostname;
    if(!$hostobj && !$agenttype) {
        die("need either hostobj or agenttype");
    }

    my $agent = build_agent($agenttype // $hostobj);
    $checks = $agent->get_services_checks($c, $hostname, $hostobj);
    set_checks_category($c, $hostobj, $checks);

    return($checks);
}

##########################################################

=head2 get_host_agent_services

    get_host_agent_services($c, $hostobj)

returns list of services for given host object.

=cut
sub get_host_agent_services {
    my($c, $hostobj) = @_;
    die("uninitialized objects database") unless $c->{'obj_db'};
    my $objects = $c->{'obj_db'}->get_services_for_host($hostobj);
    return({}) unless $objects && $objects->{'host'};
    return($objects->{'host'});
}

##########################################################

=head2 find_agent_module_names

    find_agent_module_names()

returns available agent class names

=cut
sub find_agent_module_names {
    my $modules = _find_agent_modules();
    my $list = [];
    for my $mod (@{$modules}) {
        my $name = $mod;
        $name =~ s/Thruk::Agents:://gmx;
        push @{$list}, $name;
    }
    return($list);
}

##########################################################

=head2 get_agent_class

    get_agent_class($type)

returns agent class for given type

=cut
sub get_agent_class {
    my($type) = @_;
    confess("no type") unless $type;
    my $modules  = _find_agent_modules();
    my @provider = grep { $_ =~ m/::$type$/mxi } @{$modules};
    if(scalar @provider == 0) {
        die('unknown type \''.$type.'\' in agent configuration, choose from: '.join(', ', @{find_agent_module_names()}));
    }
    return($provider[0]);
}

##########################################################

=head2 build_agent

    build_agent($hostdata | $hostobj)

returns agent based on host (livestatus) data

=cut
sub build_agent {
    my($host) = @_;
    my $c = $Thruk::Globals::c;

    my($agenttype, $hostdata);
    if(!ref $host) {
        $agenttype = $host;
        $hostdata  = {};
    }
    elsif($host->{'conf'}) {
        # host config object
        $agenttype = $host->{'conf'}->{'_AGENT'};
        $hostdata  = $host->{'conf'};
    } else {
        my $vars  = Thruk::Utils::get_custom_vars($c, $host);
        $agenttype = $vars->{'AGENT'};
        $hostdata  = $host;
    }
    my $class = get_agent_class($agenttype);
    my $agent = $class->new($hostdata);

    my $settings = $agent->settings();
    # merge some attributes to top level
    for my $key (qw/type section/) {
        $agent->{$key} = $settings->{$key} // '';
    }

    if($c->stash->{'theme'} =~ m/dark/mxi) {
        $agent->{'icon'} = $settings->{'icon_dark'};
    }
    $agent->{'icon'} = $agent->{'icon'} // $settings->{'icon'} // '';

    return($agent);
}

##########################################################

=head2 check_for_check_commands

    check_for_check_commands($c, [$extra_cmd])

create agent check commands if missing

=cut
sub check_for_check_commands {
    my($c, $agent_cmds) = @_;

    $agent_cmds = [] unless defined $agent_cmds;
    push @{$agent_cmds}, {
        command_name => 'check_thruk_agents',
        command_line => '$USER4$/bin/thruk $ARG1$',
    };

    my $changed = 0;
    for my $cmd (@{$agent_cmds}) {
        $changed++ unless _ensure_command_exists($c, $cmd->{'command_name'}, $cmd);
    }

    if($changed) {
        if($c->{'obj_db'}->commit($c)) {
            $c->stash->{'obj_model_changed'} = 1;
        }
        Thruk::Utils::Conf::store_model_retention($c, $c->stash->{'param_backend'});
    }

    return;
}

##########################################################

=head2 set_object_model

    set_object_model($c, $peer_key, [$retries])

returns 1 on success, 0 on redirects. Dies otherwise.

=cut
sub set_object_model {
    my($c, $peer_key, $retries) = @_;
    $retries = 0 unless defined $retries;

    confess("no peer key set") unless $peer_key;

    $c->stash->{'param_backend'} = $peer_key;
    delete $c->{'obj_db'};
    my $rc = Thruk::Utils::Conf::set_object_model($c, undef, $peer_key);
    if($rc == 0 && $c->stash->{set_object_model_err}) {
        if($retries < 3 && $c->stash->{"model_job"}) {
            my $is_running = Thruk::Utils::External::wait_for_job($c, $c->stash->{"model_job"}, 30);
            if(!$is_running) {
                return(set_object_model($c, $peer_key, $retries+1));
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
        _error(join("\n", @{$c->{'obj_db'}->{'errors'}}));
        die(sprintf("failed to initialize objects of peer %s", $peer_key));
    }
    return 1;
}

##########################################################

=head2 set_checks_category

    set_checks_category($c, $hostobj, $checks)

sets exists attribute for checks, can be:
 - exists: already exists as services
 - new: does not yet exist as services
 - obsolete: exists as services but not in inventory anymore
 - disabled: exists in inventory but is disabled by user config

=cut
sub set_checks_category {
    my($c, $hostobj, $checks) = @_;

    my $services = $hostobj ? get_host_agent_services($c, $hostobj) : {};

    my $settings = $hostobj->{'conf'}->{'_AGENT_CONFIG'} ? decode_json($hostobj->{'conf'}->{'_AGENT_CONFIG'}) : {};

    my $existing = {};
    for my $chk (@{$checks}) {
        my $name = $chk->{'name'};
        $existing->{$chk->{'id'}} = 1;
        my $svc = $services->{$name};
        if($svc && $svc->{'conf'}->{'_AGENT_AUTO_CHECK'}) {
            $chk->{'exists'} = 'exists';
            $chk->{'_svc'}   = $svc;
        } else {
            if($settings && $settings->{'disabled'} && Thruk::Base::array_contains($chk->{'id'}, $settings->{'disabled'})) {
                $chk->{'exists'} = 'disabled';
            } else {
                if($chk->{'disabled'}) {
                    $chk->{'exists'} = 'disabled';
                } else {
                    $chk->{'exists'} = 'new';
                }
            }
        }
    }

    for my $name (sort keys %{$services}) {
        my $svc = $services->{$name};
        my $id  = $svc->{'conf'}->{'_AGENT_AUTO_CHECK'};
        next unless $id;
        next if $existing->{$id};

        push @{$checks}, { 'id' => $id, 'name' => $name, exists => 'obsolete'};
    }

    return
}

##########################################################

=head2 to_id

    to_id($name)

returns name with special characters replaced

=cut
sub to_id {
    my($name) = @_;
    $name =~ s/[^a-zA-Z0-9._\-\/]/_/gmx;
    return($name);
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
sub _find_agent_modules {
    our $modules;
    return $modules if defined $modules;

    $modules = Thruk::Utils::find_modules('/Thruk/Agents/*.pm');
    for my $mod (@{$modules}) {
        require $mod;
        $mod =~ s/\//::/gmx;
        $mod =~ s/\.pm$//gmx;
        $mod->import;
    }
    return $modules;
}

##########################################################

1;
