use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::DNS::Server',
    'VERSION_FROM'	=> 'Server.pm', # finds $VERSION
    'PREREQ_PM'		=> {
      Net::DNS => 0.38,
      NetAddr::IP => 3.00,
      Net::DNS::Method => 0,
    },
);
