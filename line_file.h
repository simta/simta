#ifndef SIMTA_LINEFILE_H
#define SIMTA_LINEFILE_H

struct line {
    struct line		*line_next;
    struct line		*line_prev;
    char		*line_data;
    int			line_no;
};

struct line_file {
    struct line		*l_first;
    struct line		*l_last;
};

#define	NO_COPY		0
#define	COPY		1

struct line_file	*line_file_create( void );
void			line_file_free( struct line_file * );
struct line		*line_append( struct line_file *, char *, int );
struct line		*line_prepend( struct line_file *, char *, int );

#endif /* SIMTA_LINEFILE_H */
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
