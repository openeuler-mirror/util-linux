%define compldir %{_datadir}/bash-completion/completions/
%define _pre_version__ 2.32

Name:           util-linux
Version:        %{_pre_version__}.1
Release:        2
Summary:        A random collection of Linux utilities
License:        GPLv2 and GPLv2+ and LGPLv2+ and BSD with advertising and Public Domain
URL:            https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git
Source0:        https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v%{_pre_version__}/%{name}-%{version}.tar.xz
Source1:        util-linux-login.pamd
Source2:        util-linux-remote.pamd
Source3:        util-linux-chsh-chfn.pamd
Source4:        util-linux-60-raw.rules
Source5:        adjtime
Source6:        util-linux-su.pamd
Source7:        util-linux-su-l.pamd
Source8:        util-linux-runuser.pamd
Source9:        util-linux-runuser-l.pamd

BuildRequires:  audit-libs-devel >= 1.0.6 gettext-devel libselinux-devel ncurses-devel pam-devel zlib-devel popt-devel
BuildRequires:  libutempter-devel systemd-devel systemd libuser-devel libcap-ng-devel python-devel gcc gdb

Requires:       coreutils pam >= 1.1.3-7, /etc/pam.d/system-auth audit-libs >= 1.0.6 libuser
Requires:       libblkid = %{version}-%{release} libmount = %{version}-%{release} libsmartcols = %{version}-%{release}
Requires:       libfdisk = %{version}-%{release} libuuid = %{version}-%{release} systemd systemd-units shadow-utils

Conflicts:      initscripts < 9.79-4 bash-completion < 1:2.1-1 coreutils < 8.20 sysvinit-tools < 2.88-14
Conflicts:      e2fsprogs < 1.41.8-5 filesystem < 3

Provides:       eject = 2.1.6 rfkill = 0.5
Provides:       util-linux-ng = %{version}-%{release}
Provides:       /bin/dmesg /bin/kill /bin/more /bin/mount /bin/umount /sbin/blkid
Provides:       /sbin/blockdev /sbin/findfs /sbin/fsck /sbin/nologin
Provides:       libfdisk libsmartcols libmount libblkid libuuid uuidd util-linux-user
Obsoletes:      libsmartcols libfdisk libmount libblkid libuuid uuidd util-linux-user
Obsoletes:      eject <= 2.1.5 rfkill <= 0.5 util-linux-ng < 2.19

Patch0000:      2.28-login-lastlog-create.patch

Patch6000:      rename-prevent-no-act-from-setting-no-overwrite.patch
Patch6001:      bash-completion-fix-few-bash-set-u-issues.patch
Patch6002:      bash-completion-fix-typo-in-blockdev-file.patch
Patch6003:      fdisk-fix-typo-in-debug-string.patch
Patch6004:      lib-canonicalize-fix-truncation-warning.patch
Patch6005:      zramctl-fix-truncation-warning.patch
Patch6006:      last-fix-false-positive-compiler-warning.patch
Patch6007:      libfdisk-Fix-multipath-partition-seperators-for-user.patch
Patch6008:      lib-pager-fix-compiler-warning-Wrestrict.patch
Patch6009:      libfdisk-fix-compiler-warning-Wmaybe-uninitialized.patch
Patch6010:      losetup-fix-mem-leak-improve-code-coverity-scan.patch
Patch6011:      lscpu-fix-resource-leak-coverity-scan.patch
Patch6012:      lscpu-fixed-part-ID-for-ARM-Cortex-M7.patch
Patch6013:      libuuid-fix-name-based-UUIDs.patch
Patch6014:      fallocate-add-missing-semicolon.patch
Patch6015:      blkzone-fix-report-zones-sector-offset-check.patch
Patch6016:      libblkid-fix-detection-of-dm-integrity-superblock.patch
Patch6017:      fix-a-bug-where-switch_root-would-erroneously-try-to.patch
Patch6018:      libblkid-Fix-hidding-typo.patch
Patch6019:      mkswap-fix-page-size-warning-message.patch
Patch6020:      lslogins-remove-duplicate-NULL-check.patch
Patch6021:      hexdump-fix-potential-null-pointer-dereference-warni.patch
Patch6022:      chmem-add-initilizer-clang.patch
Patch6023:      libblkid-ntfs-fix-compiler-warning-Wpedantic.patch
Patch6024:      last-fix-wtmp-user-name-buffer-overflow-asan.patch
Patch6025:      various-fix-uninitialized-when-used-warnings-clang.patch
Patch6026:      include-add-no-return-function-attribute.patch
Patch6027:      agetty-Fix-input-of-non-ASCII-characters-in-get_logn.patch
Patch6028:      script-be-sensitive-to-another-SIGCHLD-ssi_codes.patch
Patch6029:      su-be-sensitive-to-another-SIGCHLD-ssi_codes.patch

%description
The util-linux package contains a random collection of files that
implements some low-level basic linux utilities.


%package devel
Summary:        Development package for ${name}
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release} pkgconfig
Provides:       libfdisk-devel libsmartcols-devel libmount-devel libblkid-devel libuuid-devel
Obsoletes:      libfdisk-devel libsmartcols-devel libmount-devel libblkid-devel libuuid-devel

%description devel
This package contains some library and other necessary files for the
development of %{name}.

%package -n python-libmount
Summary:        Python Package for the libmount library pack
Requires:       libmount = %{version}-%{release}
License:        LGPLv2+

%description -n python-libmount
This package provides python support for users to use the libmount library
to work with mount tables and mount filesystems.

%package help
Summary:        Help package for ${name}
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}

%description help
This package contains some doc and man help files for %{name}.

%prep
%autosetup -n %{name}-%{version} -p1

%build
%define _build_arg0__ CFLAGS="-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $RPM_OPT_FLAGS" SUID_CFLAGS="-fpie"
%define _build_arg1__ SUID_LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now" DAEMON_CFLAGS="$SUID_CFLAGS" DAEMON_LDFLAGS="$SUID_LDFLAGS"

unset LINGUAS || :
%configure \
  --with-systemdsystemunitdir=%{_unitdir} \
  --disable-silent-rules \
  --disable-bfs \
  --disable-pg \
  --enable-chfn-chsh \
  --enable-usrdir-path \
  --enable-write \
  --enable-raw \
  --with-python=2 \
  --with-systemd \
  --with-udev \
  --with-selinux \
  --with-audit \
  --with-utempter \
  --disable-makeinstall-chown

%make_build %{_build_arg0__} %{_build_arg1__}

%check
%if %{?_with_check:1}%{!?_with_check:0}
make check
%endif

%install
%make_install

install -d %{buildroot}%{_sysconfdir}/pam.d
install -d %{buildroot}{/run/uuidd,/var/lib/libuuid,/var/log}

mv %{buildroot}%{_sbindir}/raw %{buildroot}%{_bindir}/raw
install -m644 %{SOURCE1} %{buildroot}%{_sysconfdir}/pam.d/login
install -m644 %{SOURCE2} %{buildroot}%{_sysconfdir}/pam.d/remote
install -m644 %{SOURCE3} %{buildroot}%{_sysconfdir}/pam.d/chsh
install -m644 %{SOURCE3} %{buildroot}%{_sysconfdir}/pam.d/chfn
install -Dm644 %{SOURCE4} %{buildroot}%{_prefix}/lib/udev/rules.d/60-raw.rules
install -m644 %{SOURCE5} %{buildroot}%{_sysconfdir}/adjtime
install -m644 %{SOURCE6} %{buildroot}%{_sysconfdir}/pam.d/su
install -m644 %{SOURCE7} %{buildroot}%{_sysconfdir}/pam.d/su-l
install -m644 %{SOURCE8} %{buildroot}%{_sysconfdir}/pam.d/runuser
install -m644 %{SOURCE9} %{buildroot}%{_sysconfdir}/pam.d/runuser-l

ln -sf hwclock %{buildroot}%{_sbindir}/clock
ln -sf ../proc/self/mounts %{buildroot}/etc/mtab

touch %{buildroot}/var/log/lastlog
chmod 0644 %{buildroot}/var/log/lastlog

echo ".so man8/raw.8" > %{buildroot}%{_mandir}/man8/rawdevices.8
echo ".so man8/hwclock.8" > %{buildroot}%{_mandir}/man8/clock.8

%find_lang %name

find  %{buildroot}%{_bindir}/ -regextype posix-egrep -type l \
  -regex ".*(linux32|linux64|aarch64|i386|x86_64|uname26)$" \
  -printf "%{_bindir}/%f\n" > %{name}.files
cat %{name}.lang >> %{name}.files

find  %{buildroot}%{_mandir}/man8 -regextype posix-egrep  \
  -regex ".*(linux32|linux64|aarch64|i386|x86_64|uname26)\.8.*" \
  -printf "%{_mandir}/man8/%f*\n" > %{name}-help.files

rm -rf %{buildroot}%{_libdir}/*.{la,a}
rm -rf %{buildroot}%{_libdir}/python*/site-packages/*.{la,a}

%pre
getent group uuidd >/dev/null || groupadd -r uuidd
getent passwd uuidd >/dev/null || \
useradd -r -g uuidd -d /var/lib/libuuid -s /sbin/nologin \
    -c "UUID generator helper daemon" uuidd
exit 0

%post
/sbin/ldconfig
[ -d /var/log ] || mkdir -p /var/log

touch /var/log/lastlog
chown root:root /var/log/lastlog
chmod 0644 /var/log/lastlog

if [ -x /usr/sbin/selinuxenabled ] && /usr/sbin/selinuxenabled
then
    SECXT=`/usr/sbin/matchpathcon -n /var/log/lastlog 2> /dev/null`
    if [ -n "$SECXT" ]
    then
        /usr/bin/chcon "$SECXT"  /var/log/lastlog >/dev/null 2>&1 || :
    fi
fi
if [ ! -L /etc/mtab ]
then
    ln -sf ../proc/self/mounts /etc/mtab || :
fi

[ -d /run/blkid ] || mkdir -p /run/blkid
for i in /etc/blkid.tab /etc/blkid.tab.old \
  /etc/blkid/blkid.tab /etc/blkid/blkid.tab.old
do
    if [ -f "${i}" ]
    then
        mv "${i}" /run/blkid/ || :
    fi
done

%systemd_post uuidd
if [ $1 -eq 1 ]
then
    /bin/systemctl start uuidd > /dev/null 2>&1 || :
fi

%preun
%systemd_preun uuidd

%postun
/sbin/ldconfig
%systemd_postun_with_restart uuidd

%files -f %{name}.files
%exclude %{compldir}/{mount,umount}
%doc AUTHORS libblkid/COPYING
%{!?_licensedir:%global license %%doc}
%license Documentation/licenses/* {libfdisk,libsmartcols,libmount,libuuid}/COPYING
%config(noreplace) %{_sysconfdir}/pam.d/{login,remote,su,su-l,runuser,runuser-l,chfn,chsh}
%config(noreplace) %{_prefix}/lib/udev/rules.d/60-raw.rules
%config(noreplace) %verify(not md5 mtime size) %{_sysconfdir}/adjtime
%dir %attr(2775, uuidd, uuidd) /var/lib/libuuid
%dir %attr(2775, uuidd, uuidd) /run/uuidd
%attr(4755,root,root) %{_bindir}/mount
%attr(4755,root,root) %{_bindir}/umount
%attr(4755,root,root) %{_bindir}/su
%attr(755,root,root) %{_bindir}/login
%attr(2755,root,tty) %{_bindir}/write
%attr(4711,root,root) %{_bindir}/chfn
%attr(4711,root,root) %{_bindir}/chsh
%ghost %attr(0644,root,root) %verify(not md5 size mtime) /var/log/lastlog
%ghost %verify(not md5 size mtime) %config(noreplace,missingok) /etc/mtab
%{_unitdir}/{fstrim.*,uuidd.*}
%{_libdir}/{libfdisk.so.*,libsmartcols.so.*,libmount.so.*,libblkid.so.*,libuuid.so.*}
%{_bindir}/{cal,chrt,col,colcrt,colrm,column,chmem,dmesg,eject,fallocate,fincore,findmnt}
%{_bindir}/{flock,getopt,hexdump,ionice,ipcmk,ipcrm,ipcs,isosize,kill,last,lastb,logger}
%{_bindir}/{look,lsblk,lscpu,lsipc,lslocks,lslogins,lsmem,lsns,mcookie,mesg,more,mountpoint}
%{_bindir}/{namei,nsenter,prlimit,raw,rename,renice,rev,script,scriptreplay,setarch,setpriv}
%{_bindir}/{setsid,setterm,taskset,ul,unshare,utmpdump,uuidgen,uuidparse,wall,wdctl,whereis}
%{_sbindir}/{addpart,agetty,blkdiscard,blkid,blkzone,blockdev,chcpu,ctrlaltdel,delpart,fdisk}
%{_sbindir}/{findfs,fsck,fsck.cramfs,fsck.minix,fsfreeze,fstrim,ldattach,losetup,mkfs,mkfs.cramfs}
%{_sbindir}/{mkfs.minix,mkswap,nologin,partx,pivot_root,readprofile,resizepart,rfkill,rtcwake}
%{_sbindir}/{runuser,sulogin,swaplabel,swapoff,swapon,switch_root,wipefs,zramctl}
%{_sbindir}/{clock,fdformat,hwclock,cfdisk,sfdisk,uuidd}
%{compldir}/{addpart,blkdiscard,blkid,blkzone,blockdev,cal,chcpu,chmem,chrt,col}
%{compldir}/{colcrt,colrm,column,ctrlaltdel,delpart,dmesg,eject,fallocate,fdisk}
%{compldir}/{fincore,findfs,findmnt,flock,fsck,fsck.cramfs,fsck.minix,fsfreeze}
%{compldir}/{fstrim,getopt,hexdump,ionice,ipcmk,ipcrm,ipcs,isosize,last,ldattach}
%{compldir}/{logger,look,losetup,lsblk,lscpu,lsipc,lslocks,lslogins,lsmem,lsns}
%{compldir}/{mcookie,mesg,mkfs,mkfs.cramfs,mkfs.minix,mkswap,more,mountpoint}
%{compldir}/{namei,nsenter,partx,pivot_root,prlimit,raw,readprofile,rename,renice}
%{compldir}/{resizepart,rev,rfkill,rtcwake,runuser,script,scriptreplay,setarch}
%{compldir}/{setpriv,setsid,setterm,su,swaplabel,swapoff,swapon,taskset,ul,unshare}
%{compldir}/{utmpdump,uuidgen,uuidparse,wall,wdctl,whereis,wipefs,write,zramctl}
%{compldir}/{fdformat,hwclock,cfdisk,sfdisk,chfn,chsh,uuidd}

%files devel
%{_includedir}/{libfdisk,libsmartcols,uuid,blkid,libmount}
%{_libdir}/{libfdisk.so,libsmartcols.so,libuuid.so,libblkid.so,libmount.so}
%{_libdir}/pkgconfig/{fdisk.pc,smartcols.pc,uuid.pc,blkid.pc,mount.pc}

%files -n python-libmount
%{!?_licensedir:%global license %%doc}
%license Documentation/licenses/COPYING.LGPLv2.1 libmount/COPYING
%{_libdir}/python*/site-packages/libmount/

%files help -f %{name}-help.files
%exclude %{_datadir}/doc/util-linux/getopt/*
%doc README NEWS Documentation/deprecated.txt
%doc %attr(0644,-,-) misc-utils/getopt-*.{bash,tcsh}
%{_mandir}/man1/{chfn.1*,chsh.1*,cal.1*,chrt.1*,col.1*,colcrt.1*,colrm.1*,column.1*,dmesg.1*,eject.1*}
%{_mandir}/man1/{fallocate.1*,fincore.1*,flock.1*,getopt.1*,hexdump.1*,ionice.1*,ipcmk.1*,ipcrm.1*,ipcs.1*}
%{_mandir}/man1/{kill.1*,last.1*,lastb.1*,logger.1*,login.1*,look.1*,lscpu.1*,lsipc.1*,lslogins.1*,lsmem.1*}
%{_mandir}/man1/{mcookie.1*,mesg.1*,more.1*,mountpoint.1*,namei.1*,nsenter.1*,prlimit.1*,rename.1*,renice.1*}
%{_mandir}/man1/{rev.1*,runuser.1*,script.1*,scriptreplay.1*,setpriv.1*,setsid.1*,setterm.1*,su.1*,taskset.1*}
%{_mandir}/man1/{ul.1*,unshare.1*,utmpdump.1.gz,uuidgen.1*,uuidparse.1*,wall.1*,whereis.1*,write.1*}
%{_mandir}/man3/{libblkid.3*,uuid.3*,uuid_clear.3*,uuid_compare.3*,uuid_copy.3*,uuid_generate.3*,uuid_generate_random.3*}
%{_mandir}/man3/{uuid_generate_time_safe.3*,uuid_is_null.3*,uuid_parse.3*,uuid_time.3*,uuid_unparse.3*,uuid_generate_time.3*}
%{_mandir}/man5/{fstab.5*,terminal-colors.d.5*}
%{_mandir}/man8/{uuidd.8*,fdformat.8*,hwclock.8*,clock.8*,cfdisk.8*,sfdisk.8*,addpart.8*,agetty.8*}
%{_mandir}/man8/{blkdiscard.8*,blkid.8*,blkzone.8*,blockdev.8*,chcpu.8*,chmem.8*,ctrlaltdel.8*,delpart.8*}
%{_mandir}/man8/{fdisk.8*,findfs.8*,findmnt.8*,fsck.8*,fsck.cramfs.8*,fsck.minix.8*,fsfreeze.8*,fstrim.8*}
%{_mandir}/man8/{isosize.8*,ldattach.8*,losetup.8*,lsblk.8*,lslocks.8*,lsns.8*,mkfs.8*,mkfs.cramfs.8*}
%{_mandir}/man8/{mkfs.minix.8*,mkswap.8*,mount.8*,nologin.8*,partx.8*,pivot_root.8*,raw.8*,rawdevices.8*}
%{_mandir}/man8/{readprofile.8*,resizepart.8*,rfkill.8*,rtcwake.8*,setarch.8*,sulogin.8.gz,swaplabel.8*}
%{_mandir}/man8/{swapoff.8*,swapon.8*,switch_root.8*,umount.8*,wdctl.8.gz,wipefs.8*,zramctl.8*}

%changelog
* Sat Sep 21 2019 huzhiyu<huzhiyu1@huawei.com> - 2.32.1-2
- Package init
