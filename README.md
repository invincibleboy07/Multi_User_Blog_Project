# Multi User Blog
This project is all about a blog website which allows multiple users to post their blog in the website and also provides various other features like edit, delete, like post and comments with some restrictions.

## See it live:
You can see the project live [here](https://hello-world-156305.appspot.com/)
## Contents:
* Requirements and Installation
* What's Used?
* What's Inside?
* License

## Languages and Frameworks used
* Google App Engine
* Backend
    1) Python.
    2) Jinja
* Front-End
    1) HTML5
    2) CSS3 with Bootstrap
    3) Javascript

## Requirements and Installation
This project works on Google App Engine hence you need to instal GAE. Steps for installation for GAE and other things is given below: 
* Python is used hence install python from [here](https://www.python.org/downloads/)
* Install and configure Google App Engine from [here](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python)
* You need to create your  Google App Engine Account to host projects.
* Further assistance for GAE installation and configuration can be found [here](https://drive.google.com/file/d/0Byu3UemwRffDbjd0SkdvajhIRW8/view)
* Run Localhost server, make changes as per needed and test locally.
* Finally upload to Google App engine as given in above assistance link.
* Now you can access from the unique url provided after you uploaded.

## What's Inside?
This project contains following files and folders:

```
Multi User Blog Project
|   blog.py
|   app.yaml
|
|___static
|   |___css ( contains all css styling )
|   |___img ( All images and icons used )
|   |___js ( All javascript files used )
|
|___templates 
|   |___base.html
|   |___credits.html
|   |___editcomment.html
|   |___editpost.html
|   |___ .... ( All html markup file )

```
### blog. py
This is the main python file that contains all handlers and logic for backend. You can modify as needed as per the comments given inside.
### app. yaml
It specifies runtime configuration, including versions and URLs. Further information about app. yaml can be found [here](https://cloud.google.com/appengine/docs/flexible/python/configuring-your-app-with-app-yaml) 
### static
It contains css, img and js folders that contains css files for styling, images and icons used in project and javascript files used respectively.

### templates
It contains all HTML files that are used for layout. It contains:
* base.html ( This is the base layout used by all pages with help of jinja)
* front.html ( This displays all the blog post for preview )
* editpost.html ( This displays the editing page for post )
* ......and soon. ( You can easily understand what each html does with comments included inside ) 

## License
* Icons made by Iconnice from www.flaticon.com is licensed by CC 3.0 BY
* Icons made by Madebyoliver from www.flaticon.com is licensed by CC 3.0 BY
* Icons made by Madebyoliver from www.flaticon.com is licensed by CC 3.0 BY
* Fonts: GOOGLE FONTS
* bootstrap framework from [Bootstrap](http://getbootstrap.com/)



