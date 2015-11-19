# EphingLab
Creates test lab and allows the user to run their own scripts and files to customize the lab as they see fit.

This project was created because of how complicated Microsoft's PDT is. The PDT is a very powerful tool that is solid when it is set up correctly, but it is not very forgiving for problems and can be difficult to troubleshoot. Another issue with the PDT is it is not very extendable. It is hard to add customizations to make the environment your own.

I decided to make these functions to fix the issues above. This is designed to do much less than the PDT, but enable you to do more. The script will create a domain controller VM and then other VMs based on an XML file. It will copy over folders to the root of C on the VMs so needed media can be added to the server, and then can run a script when the computer boots up that will do whatever you want.  All servers created will have PS remoting enabled and the firewalls off, so this will help set up remote servers. 

Feel free to contribute to this product with any install scripts you create

Features:
Creates VMs based on XML file
Automatically creates one domain controller
Copies folders to the root of C of VMs created
Runs scripts at startup of the VM
Domain joins all VMs to the domain specified in the XML file

To Do:
Enable customizations to the DC when it is created
Finish install scripts for common products (SCCM, SCSM, SCORCH, Exchange, SQL, etc...)
Add checks to make sure all information needed is given
Add help parameters
