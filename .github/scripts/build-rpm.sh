#!/usr/bin/env bash
set -euo pipefail

source /etc/os-release
case ${DISTRO_FAMILY:-} in
  fedora) ;;
  *) printf 'Unsupported DISTRO_FAMILY: %s\n' "${DISTRO_FAMILY:-unset}" >&2; exit 2 ;;
esac

if [[ ${ID:-} != "$DISTRO_FAMILY" ]]; then
  printf 'Container ID does not match DISTRO_FAMILY\n' >&2
  exit 2
fi

root=$(pwd -P)
DISTRO_ID="${ID}-${VERSION_ID}"
[[ -f $root/meson.build ]]

dnf install -y \
  rpm-build rpmdevtools gcc gcc-c++ meson ninja-build cmake \
  glib2-devel libgusb-devel pixman-devel systemd-devel libgudev-devel \
  openssl-devel opencv-devel gobject-introspection-devel cairo-devel \
  doctest-devel python3-cairo python3-gobject

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp "$root/packaging/fedora/libfprint.spec" "$work/rpmbuild/SPECS/"

tar --exclude=.git --exclude=builddir --exclude=artifacts \
    --transform="s,^\.,libfprint-fpc1022-1.95.0," \
    -czf "$work/rpmbuild/SOURCES/libfprint-fpc1022-1.95.0.tar.gz" .

rpmbuild --define "_topdir $work/rpmbuild" -ba "$work/rpmbuild/SPECS/libfprint.spec"

out="$root/artifacts/$DISTRO_ID"
mkdir -p "$out"
find "$work/rpmbuild/RPMS" -name "*.rpm" -exec cp {} "$out/" \;
