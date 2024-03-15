#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <string>

FILE *interfaceFile(std::string sockPath) {
  struct stat sbuf;
  struct sockaddr_un addr = { .sun_family = AF_UNIX };
  int fd = -1, ret;
  FILE *f = NULL;

  errno = EINVAL;
  ret = snprintf(addr.sun_path, sizeof(addr.sun_path), sockPath.c_str());
  if (ret < 0)
    goto out;

  ret = stat(addr.sun_path, &sbuf);
  if (ret < 0)
    goto out;

  errno = EBADF;
  if (!S_ISSOCK(sbuf.st_mode))
    goto out;

  ret = fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ret < 0)
    goto out;

  ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0) {
    if (errno == ECONNREFUSED) /* If the process is gone, we try to clean up the socket. */
      unlink(addr.sun_path);
    goto out;
  }
  f = fdopen(fd, "r+");
  if (f)
    errno = 0;
out:
  ret = -errno;
  if (ret) {
    if (fd >= 0)
      close(fd);
    errno = -ret;
    return NULL;
  }
  return f;
}