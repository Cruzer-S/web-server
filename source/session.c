#include "session.h"

#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>

SessionPrivate session_create(int fd, SSL_CTX *ctx, EventCallback callback)
{
	SessionPrivate session;

	session = malloc(sizeof(struct session_private));
	if (session == NULL)
		goto RETURN_NULL;

	session->id = fd;

	session->server = NULL;
	session->body = NULL;
	session->header.field_head = NULL;
	session->headerlen = session->bodylen = 0;
	session->progress = SESSION_PROCESS_READ_HEADER;

	session->object = event_object_create(
		fd, true, session, callback
	);
	if (session->object == NULL)
		goto FREE_SESSION;

	if (ctx) {
		session->ssl = SSL_new(ctx);
		if (session->ssl == NULL)
			goto DESTROY_OBJECT;

		if (SSL_set_fd(session->ssl, fd) != 1)
			goto FREE_SSL;

	} else {
		session->ssl = NULL;
	}

	return session;

FREE_SSL:	SSL_free(session->ssl);
DESTROY_OBJECT:	event_object_destroy(session->object);
FREE_SESSION:	free(session);
RETURN_NULL:	return NULL;
}

void session_destroy(SessionPrivate session)
{
	int fd = event_object_get_fd(session->object);

	if (session->ssl)
		SSL_free(session->ssl);

	event_object_destroy(session->object);

	free(session);
}

int session_write(SessionPrivate session, void *buffer, int size)
{
	ssize_t len;

	if (session->ssl) {
		len = SSL_write(session->ssl, buffer, size);

		if (len <= 0)
			return -1;
	} else {
		int fd = event_object_get_fd(session->object);

		len = write(fd, buffer, size);
		if (len == -1)
			return -1;
	}

	return len;
}

int session_read(SessionPrivate session, void *buffer, int size)
{
	ssize_t len;

	if (session->ssl) {
		len = SSL_read(session->ssl, buffer, size);

		if (len <= 0) {
			int ret = SSL_get_error(session->ssl, len);
			if (ret == SSL_ERROR_WANT_READ)
				return -1;

			if (ret == SSL_ERROR_ZERO_RETURN)
				return 0;

			return -2;
		}
	} else {
		int fd = event_object_get_fd(session->object);

		len = recv(fd, buffer, size, 0);
		if (len == -1) {
			if (errno == EAGAIN)
				return -1;

			return -2;
		}

		if (len == 0)
			return 0;
	}

	return len;
}
