/*
* database_statements.h - written by ale in milano on 16oct2012
* list of statements, included multiple times

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

#if !defined DATABASE_STATEMENT
#error Must define the macro before inclusion
#endif

DATABASE_STATEMENT(db_sql_whitelisted)
DATABASE_STATEMENT(db_sql_select_domain)
DATABASE_STATEMENT(db_sql_update_domain)
DATABASE_STATEMENT(db_sql_insert_domain)
DATABASE_STATEMENT(db_sql_insert_msg_ref)
DATABASE_STATEMENT(db_sql_insert_message)
DATABASE_STATEMENT(db_sql_select_user)
DATABASE_STATEMENT(db_sql_select_target)
DATABASE_STATEMENT(db_sql_update_target)
DATABASE_STATEMENT(db_sql_insert_target)
DATABASE_STATEMENT(db_sql_insert_target_ref)
DATABASE_STATEMENT(db_sql_check_user)

