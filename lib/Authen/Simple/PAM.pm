package Authen::Simple::PAM;

use strict;
use warnings;
use base 'Authen::Simple::Adapter';

use Authen::PAM;
use Params::Validate qw[];

our $VERSION = 0.1;

__PACKAGE__->options({
    service => {
        type     => Params::Validate::SCALAR,
        default  => 'login',
        optional => 1
    }
});

sub check {
    my ( $self, $username, $password ) = @_;

    my $service = $self->service;
    my $handler = sub {
        my @response = ();

        while (@_) {
            my $code    = shift;
            my $message = shift;
            my $answer  = undef;

            if ( $code == PAM_PROMPT_ECHO_ON ) {
                $answer = $username;
            }

            if ( $code == PAM_PROMPT_ECHO_OFF ) {
                $answer = $password;
            }

            push( @response, PAM_SUCCESS, $answer );
        }

        return ( @response, PAM_SUCCESS );
    };


    my $pam = Authen::PAM->new( $service, $username, $handler );

    unless ( ref $pam ) {

        my $error = undef;

        if ( $pam == PAM_SERVICE_ERR ) {
            $error = 'Error in service module.';
        }

        if ( $pam == PAM_SYSTEM_ERR ) {
            $error = 'System error.';
        }

        if ( $pam == PAM_BUF_ERR ) {
            $error = 'Memory buffer error.';
        }

        $error ||= "Unknown error has occurred with code '$pam'.";

        $self->log->error( qq/Failed to authenticate user '$username' using service '$service'. Reason: '$error'/ )
          if $self->log;

        return 0;
    }

    my $result = $pam->pam_authenticate;

    unless ( $result == PAM_SUCCESS ) {

        my $error = undef;

        if ( $result == PAM_AUTH_ERR ) {
            $error = 'Authentication failure.';
        }

        if ( $result == PAM_CRED_INSUFFICIENT ) {
            $error = 'Cannot access authentication data due to insufficient credentials.';
        }

        if ( $result == PAM_AUTHINFO_UNAVAIL ) {
            $error = 'Underlying authentication service cannot retrieve authentication information.';
        }

        if ( $result == PAM_USER_UNKNOWN ) {
            $error = 'User not known to the underlying authentication module.';
        }

        if ( $result == PAM_MAXTRIES ) {
            $error = 'An authentication service has maintained a retry count which has been reached.';
        }

        $error ||= "Unknown error has occurred with code '$result'.";

        $self->log->debug( qq/Failed to authenticate user '$username' using service '$service'. Reason: '$error'/ )
          if $self->log;

        return 0;
    }

    $result = $pam->pam_acct_mgmt;

    unless ( $result == PAM_SUCCESS ) {

        my $error = undef;

        if ( $result == PAM_PERM_DENIED ) {
            $error = 'Permission denied.';
        }

        if ( $result == PAM_AUTHTOK_ERR ) {
            $error = 'A failure occurred while updating the authentication token.';
        }

        if ( $result == PAM_USER_UNKNOWN ) {
            $error = 'The user is not known to the authentication module.';
        }

        if ( $result == PAM_TRY_AGAIN ) {
            $error = 'Preliminary checks for changing the password have failed. Try again later.';
        }

        $error ||= "Unknown error has occurred with code '$result'.";

        $self->log->debug( qq/Failed to authenticate user '$username' using service '$service'. Reason: '$error'/ )
          if $self->log;

        return 0;
    }

    $self->log->debug( qq/Successfully authenticated user '$username' using service '$service'./ )
      if $self->log;

    return 1;
}

1;

__END__

=head1 NAME

Authen::Simple::PAM - Simple PAM authentication

=head1 SYNOPSIS

    use Authen::Simple::PAM;
    
    my $pam = Authen::Simple::PAM->new(
        service => 'login'
    );
    
    if ( $pam->authenticate( $username, $password ) ) {
        # successfull authentication
    }
    
    # or as a mod_perl Authen handler

    PerlModule Authen::Simple::Apache
    PerlModule Authen::Simple::PAM

    PerlSetVar AuthenSimplePAM_service "login"

    <Location /protected>
      PerlAuthenHandler Authen::Simple::PAM
      AuthType          Basic
      AuthName          "Protected Area"
      Require           valid-user
    </Location>

=head1 DESCRIPTION

PAM authentication.

=head1 METHODS

=over 4

=item * new

This method takes a hash of parameters. The following options are
valid:

=over 8

=item * service

PAM service. Defaults to C<login>.

    service => 'sshd'

=item * log

Any object that supports C<debug>, C<info>, C<error> and C<warn>.

    log => Log::Log4perl->get_logger('Authen::Simple::PAM')

=back

=item * authenticate( $username, $password )

Returns true on success and false on failure.

=back

=head1 SEE ALSO

L<Authen::Simple>.

L<Authen::PAM>.

=head1 AUTHOR

Christian Hansen C<ch@ngmedia.com>

=head1 COPYRIGHT

This program is free software, you can redistribute it and/or modify 
it under the same terms as Perl itself.

=cut
