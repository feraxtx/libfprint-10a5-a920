Name:           libfprint-fpc1022
Version:        1.95.0
Release:        1%{?dist}
Summary:        Asynchronous library for fingerprint readers with FPC 10a5:a920 support

License:        LGPL-2.1-or-later
URL:            https://github.com/feraxtx/libfprint-10a5-a920
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  pkgconfig(glib-2.0) >= 2.68
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(gobject-2.0)
BuildRequires:  pkgconfig(gobject-introspection-1.0)
BuildRequires:  pkgconfig(gusb) >= 0.4.0
BuildRequires:  pkgconfig(pixman-1)
BuildRequires:  pkgconfig(libudev)
BuildRequires:  pkgconfig(gudev-1.0)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(opencv4)
BuildRequires:  pkgconfig(cairo)
BuildRequires:  systemd-rpm-macros

Provides:       libfprint = %{version}-%{release}
Provides:       libfprint%{?_isa} = %{version}-%{release}
Conflicts:      libfprint

%description
libfprint library with support for FPC Disum (10a5:a920) match-on-host
fingerprint sensors.

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
Provides:       libfprint-devel = %{version}-%{release}
Conflicts:      libfprint-devel

%description    devel
Development headers and libraries for %{name}.

%prep
%autosetup -n %{name}-%{version}

%build
%meson \
    -Ddrivers=all \
    -Ddoc=false \
    -Dinstalled-tests=false \
    -Dudev_hwdb=enabled
%meson_build

%install
%meson_install

%check
%meson_test

%files
%license COPYING
%doc README.md
%{_libdir}/libfprint-2.so.*
%{_libdir}/girepository-1.0/FPrint-2.0.typelib
%{_datadir}/metainfo/org.freedesktop.libfprint.metainfo.xml
%{_udevrulesdir}/70-libfprint-2.rules
%{_udevhwdbdir}/60-autosuspend-libfprint-2.hwdb

%files devel
%{_includedir}/libfprint-2/
%{_libdir}/libfprint-2.so
%{_libdir}/pkgconfig/libfprint-2.pc
%{_datadir}/gir-1.0/FPrint-2.0.gir

%changelog
* Thu Oct 08 2026 feraxhp <feraxhp+gh@gmail.com> - 1.95.0-1
- Release 1.95.0 with production-ready FPC 10a5:a920 driver
- Fix overheating shutdown bug, add memory cleansing, unit tests and packaging
