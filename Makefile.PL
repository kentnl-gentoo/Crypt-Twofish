use ExtUtils::MakeMaker;

sub MY::postamble { "tables.h: tab/tables.pl\n\tperl tab/tables.pl\n" }

WriteMakefile(
    NAME          => 'Crypt::Twofish',
    OBJECT        => 'Twofish.o _twofish.o',
    VERSION_FROM  => 'Twofish.pm',
    ABSTRACT_FROM => 'Twofish.pm',
    depend        => { '_twofish.c' => 'tables.h' },
);
