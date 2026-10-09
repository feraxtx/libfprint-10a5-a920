Name:           libfprint-fpc1022
Version:        1.94.100
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
BuildRequires:  pkgconfig(gusb) >= 0.4.0
BuildRequires:  pkgconfig(pixman-1)
BuildRequires:  pkgconfig(libudev)
BuildRequires:  pkgconfig(gudev-1.0)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(opencv4)
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
%{_udevrulesdir}/60-libfprint-2-autosuspend.rules
%{_udevhwdbdir}/60-autosuspend.hwdb

%files devel
%{_includedir}/libfprint-2/
%{_libdir}/libfprint-2.so
%{_libdir}/pkgconfig/libfprint-2.pc

%changelog
* Wed Oct 08 2026 feraxhp <feraxhp+gh@gmail.com> - 1.94.100-1
- Initial release with FPC 10a5:a920 driver support
