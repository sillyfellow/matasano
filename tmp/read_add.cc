/*
 * ===========================================================================
 *
 *       Filename:  read_add.cc
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  18/05/13 14:33:08
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dr. Sadanandan (GS ZZ9 Plural Zα), grep@whybenormal.org
 *        Company:  
 *
 * ===========================================================================
 */

#include "io.h"

int main(int argc, char *argv[])
{
	WriteAnswer(ReadNumber() + ReadNumber());
	return 0;
}
