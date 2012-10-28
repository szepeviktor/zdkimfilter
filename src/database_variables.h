/*
* database_variables.h - written by ale in milano on 29sep2012
* list of variables, included multiple times

Copyright (C) 2012 Alessandro Vesely

This file is part of zdkimfilter

zdkimfilter is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

zdkimfilter is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License version 3
along with zdkimfilter.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPLv3 section 7:

If you modify zdkimfilter, or any covered work, by linking or combining it
with OpenDKIM, containing parts covered by the applicable licence, the licensor
or zdkimfilter grants you additional permission to convey the resulting work.
*/

#if !defined DATABASE_VARIABLE
#error Must define the macro before inclusion
#endif

DATABASE_VARIABLE(domain)
DATABASE_VARIABLE(local_part)
DATABASE_VARIABLE(user_ref)
DATABASE_VARIABLE(ino)
DATABASE_VARIABLE(mtime)
DATABASE_VARIABLE(pid)
DATABASE_VARIABLE(domain_ref)
DATABASE_VARIABLE(auth_type)
DATABASE_VARIABLE(ip)
DATABASE_VARIABLE(date)
DATABASE_VARIABLE(envelope_sender)
DATABASE_VARIABLE(from)
DATABASE_VARIABLE(subject)
DATABASE_VARIABLE(message_id)
DATABASE_VARIABLE(content_type)
DATABASE_VARIABLE(content_encoding)
DATABASE_VARIABLE(received_count)
DATABASE_VARIABLE(signatures_count)
DATABASE_VARIABLE(mailing_list)
DATABASE_VARIABLE(adsp_flags)
DATABASE_VARIABLE(message_status)
DATABASE_VARIABLE(vbr_mv)
DATABASE_VARIABLE(vbr_response)
DATABASE_VARIABLE(reputation)
DATABASE_VARIABLE(message_ref)

