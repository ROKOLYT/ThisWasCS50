# CS50 Password Manager
#### Video Demo:  https://youtu.be/25G5IKroASs
#### Description:
#### Overview:
This is my implementation of a password manager. It allows the user to register as a user and login. Each user can add, delete and edit their entries which include: 
+ Name
+ Url
+ Username
+ Password

To implement most of my "website" I used bootstrap. I very much liked the aesthetics and am especially proud of the popup that appears when editing an entry. Also making buttons copy username and password was a good learning experience as I have never created a function in js that takes params.
#### Details:
I didn't change anything in helpers.py, layout.html login.html, apology.html and register.html and left it as was in the finance pset. I did however add add.html that is used to add entries to the database. In the database itself I created 2 tables: users and credentials. The users table works on the same principle as in finance pset. The credentials table has an id column that is used to identify each specific entry for credentials saved, user_id to confirm whether the current user should have access to it and the data that follows username, password, url and name. I spent most of my time writing index.html in which it creates a table with all entries. I created a function that copies passed param to the clipboard using js. It's used to copy username or password. The Edit button refernces a modal that appears after it is clicked. In the modal itself that's implemented using bootstrap I added fields to edit the entry data. In the app.py it checkes whether the user changed something and whether the user has permission to the entry and then updates it by posting to the / path. The remove button works similarly to the edit modal in the sense that it also checks for permission and then deletes the entry by going to /remove.
#### Final Project Backstory:
I spent a lot of time thinking what my final project should be. At first I was thinking about making a project in python using EasyOCR [Python library]. I'm quite familiar with OCR as I created bots using it to farm in games when I was AFK, though I used pyTesseract back then. I wanted to create a translator for documents, which I already had some experience with as I helped with https://github.com/dmMaze/BallonsTranslator which is a manga translator. I scrapped that idea as I came to conclusion that my final project should be a representation of what I learned during the course and not of what I already could do. My second idea was to make a windows application that would organize notifications from multiple socialmedia platforms in one place. This idea seemed also doable as I already created a GUI in python twice and have experience using APIs and doing webscraping. But I also scrapped this idea as I thought that doing webscraping which could be considered bad or "immoral" in my final project wasn't a good idea. Lastly I was looking through the final project gallery and I stumbled upon a To-Do list web-based project. I already had the idea but thought that It'd be too easy as a final project and then I realised that I could make a password manager as I use one everyday! It'd perfecly represent what I learned as I have never before worked with databases and only slightly touched HTML in my life! In the end this is what I created. The time I spent brainstorming could very well rival the time I spent creating the password manager. And on a final note: <h1> This Was CS50 <h1> 