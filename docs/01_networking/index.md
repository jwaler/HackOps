# 🚀 Scénario de Test – Exemple de Template

Bienvenue dans le template **HackOps**.  
Ce fichier te montre comment utiliser toutes les fonctionnalités utiles.  

---

## 📝 Introduction

Ceci est une page de test avec différents **éléments** : images, callouts, code, tags et plus.

---

## 📌 Callouts (Admonitions)

!!! info "Information"
    Ceci est un callout *info*.

!!! warning "Attention"
    ⚠️ Attention à ne pas exécuter cette commande en production !

!!! success "Succès"
    ✅ Cette étape a fonctionné.

??? note "Détails cachés"
    Tu peux aussi utiliser les callouts *repliables* (`???`).

> [!tip]  
> Ceci est un callout **style Obsidian** → fonctionne si tu as bien configuré `pymdownx.blocks.admonition`.

---

## 🖼️ Images

Image stockée localement dans `docs/images/` :  

![Logo HackOps](images/logo.png){ width="300" }

Image externe (redimensionnée) :  

![Externe](https://placekitten.com/400/300){ width="200" }

---

## 🔗 Liens

- Lien **interne** : [Retour à l’accueil](index.md)  
- Lien **externe** : [Visiter HackTricks](https://book.hacktricks.xyz/)  

---

## 💻 Code Blocks

```bash
# Exemple de commande bash
nmap -A -p- 192.168.1.10
