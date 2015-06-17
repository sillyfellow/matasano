/*
 * ===========================================================================
 *
 *       Filename:  io.cpp
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  18/05/13 14:37:17
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dr. Sadanandan (GS ZZ9 Plural Zα), grep@whybenormal.org
 *        Company:  
 *
 * ===========================================================================
 */

#include <iostream> 

int ReadNumber()
{
	using namespace std;
	int x;
	cout << "Give me the number: ";
	cin >> x;
	return x;
}

void WriteAnswer(int ans)
{
	using namespace std;
	cout << "The result is: " << ans << endl;
}
