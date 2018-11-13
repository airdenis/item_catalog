from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///catalogitem.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

user1 = User(
        name='Denis Ceban',
        email='airdenis09@gmail.com',
        image='profile_images/profile.png'
        )
session.add(user1)
session.commit()

category1 = Category(name='Soccer')
session.add(category1)
session.commit()

item1 = Item(
        title='Football boots',
        description='''Football boots, called cleats or soccer shoes
        in North America, are an item of footwear worn when playing
        football. Those designed for grass pitches have studs on the
        outsole to aid grip.''',
        image='item_images/sport-goods.jpg',
        category=category1,
        user=user1
        )
session.add(item1)
session.commit()

item2 = Item(
        title='Shin guard',
        description='''A shin guard or shin pad is a piece of equipment
            worn on the front of a player\'s shin to protect them
            from injury.''',
        image='item_images/sport-goods.jpg',
        category=category1,
        user=user1
        )
session.add(item2)
session.commit()

item3 = Item(
        title='Soccer uniform',
        description='''A uniform is a type of clothing worn by members of
        an organization while participating in that organization's activity.
        Modern uniforms are most often worn by armed forces and paramilitary
        organizations such as police, emergency services, security guards,
        in some workplaces and schools and by inmates in prisons.''',
        image='item_images/sport-goods.jpg',
        category=category1,
        user=user1
        )
session.add(item3)
session.commit()

item4 = Item(
        title='Soccer Socks',
        description='''A sock is an item of clothing worn on the feet and often
        covering the ankle or some part of the calf. Some type of shoe or boot
        is typically worn over socks. In ancient times, socks were made from
        leather or matted animal hair. In the late 16th century, machine-knit
        socks were first produced.''',
        image='item_images/sport-goods.jpg',
        category=category1,
        user=user1
        )
session.add(item4)
session.commit()

item5 = Item(
        title='Soccer Balls',
        description='''A football, soccer ball, or association football ball is
        the ball used in the sport of association football. The title of the
        ball varies according to whether the sport is called "football",
        "soccer", or "association football".''',
        image='item_images/sport-goods.jpg',
        category=category1,
        user=user1
        )
session.add(item5)
session.commit()


category2 = Category(name='Basketball')
session.add(category2)
session.commit()

item6 = Item(
        title='Basketball Shoes',
        description='''A shoe is an item of footwear intended to protect and
        comfort the human foot while the wearer is doing various activities.
        Shoes are also used as an item of decoration and fashion. The design
        of shoes has varied enormously through time and from culture to
        culture, with appearance originally being tied to function.''',
        image='item_images/sport-goods.jpg',
        category=category2,
        user=user1
        )
session.add(item6)
session.commit()

item7 = Item(
        title='Basketball Backboards',
        description='''A backboard is a piece of basketball equipment.
        It is a raised vertical board with an attached basket consisting of a
        net suspended from a hoop. It is made of a flat, rigid piece of, often
        Plexiglas or tempered glass which also has the properties of safety
        glass when accidentally shattered.''',
        image='item_images/sport-goods.jpg',
        category=category2,
        user=user1
        )
session.add(item7)
session.commit()

item8 = Item(
        title='Basketball Uniform',
        description='''A uniform is a type of clothing worn by members of
        an organization while participating in that organization's activity.
        Modern uniforms are most often worn by armed forces and paramilitary
        organizations such as police, emergency services, security guards,
        in some workplaces and schools and by inmates in prisons.''',
        image='item_images/sport-goods.jpg',
        category=category2,
        user=user1
        )
session.add(item8)
session.commit()

item9 = Item(
        title='Shot clock',
        description='''A shot clock is used in basketball to quicken the pace
        of the game. The shot clock is usually displayed above the backboard
        behind each goal. The shot clock times a play and provides that a team
        on offense that does not promptly try to score points loses possession
        of the ball.''',
        image='item_images/sport-goods.jpg',
        category=category2,
        user=user1
        )
session.add(item9)
session.commit()

item10 = Item(
        title='Basketball ball',
        description='''A basketball is a spherical ball used in basketball games.
        Basketballs typically range in size from very small promotional items
        only a few inches in diameter to extra large balls nearly a foot in
        diameter used in training exercises. ... High school and junior leagues
        normally use NCAA, NBA or WNBA sized balls.''',
        image='item_images/sport-goods.jpg',
        category=category2,
        user=user1
        )
session.add(item10)
session.commit()


category3 = Category(name='Baseball')
session.add(category3)
session.commit()

item11 = Item(
        title='Baseball glove',
        description='''A baseball glove or mitt is a large leather glove worn by
        baseball players of the defending team, which assists players in
        catching and fielding balls hit by a batter or thrown by a
        teammate.''',
        image='item_images/sport-goods.jpg',
        category=category3,
        user=user1
        )
session.add(item11)
session.commit()

item12 = Item(
        title='Baseball Helmet',
        description='''A batting helmet is worn by batters in the game of
        baseball or softball. It is meant to protect the batter's head from
        errant pitches thrown by the pitcher. A batter who is "hit by pitch,"
        due to an inadvertent wild pitch or a pitcher's purposeful attempt to
        hit him, may be seriously, even fatally, injured.''',
        image='item_images/sport-goods.jpg',
        category=category3,
        user=user1
        )
session.add(item12)
session.commit()

item13 = Item(
        title='Baseball Uniform',
        description='''A baseball uniform is a type of uniform worn by baseball
        players and, uniquely to baseball, coaches. Most baseball uniforms have
        the titles and uniform numbers of players who wear them, usually on the
        backs of the uniforms to distinguish players from each other.''',
        image='item_images/sport-goods.jpg',
        category=category3,
        user=user1
        )
session.add(item13)
session.commit()

item14 = Item(
        title='Baseball Bat',
        description='''A baseball bat is a smooth wooden or metal club used
        in the sport of baseball to hit the ball after it is thrown by the
        pitcher. By regulation it may be no more than 2.75 inches (70 mm) in
        diameter at the thickest part and no more than 42 inches (1,100 mm)
        long''',
        image='item_images/sport-goods.jpg',
        category=category3,
        user=user1
        )
session.add(item14)
session.commit()

item15 = Item(
        title='Baseball ball',
        description='''Baseball is a bat-and-ball game played between two
        opposing teams who take turns batting and fielding. The game proceeds
        when a player on the fielding team, called the pitcher, throws a ball
        which a player on the batting team tries to hit with a bat.''',
        image='item_images/sport-goods.jpg',
        category=category3,
        user=user1
        )
session.add(item15)
session.commit()


category4 = Category(name='Frisbee')
session.add(category4)
session.commit()

item16 = Item(
        title='Frisbee Disk',
        description='''In order to play ultimate frisbee you a need a frisbee
        (makes sense). The regulation size for a frisbee is 175 gram disc. ''',
        image='item_images/sport-goods.jpg',
        category=category4,
        user=user1
        )
session.add(item16)
session.commit()

item17 = Item(
        title='Cones',
        description='''In order to properly play ultimte frisbee you need to
        label the endzones. the endzones are exactly. If you don't have cones,
        you can use shoes if you don't have cones with you. ''',
        image='item_images/sport-goods.jpg',
        category=category4,
        user=user1
        )
session.add(item17)
session.commit()

item18 = Item(
        title='Frisbee Uniform',
        description='''A uniform is a type of clothing worn by members of
        an organization while participating in that organization's activity.
        Modern uniforms are most often worn by armed forces and paramilitary
        organizations such as police, emergency services, security guards,
        in some workplaces and schools and by inmates in prisons.''',
        image='item_images/sport-goods.jpg',
        category=category4,
        user=user1
        )
session.add(item18)
session.commit()

category5 = Category(name='Snowboarding')
session.add(category5)
session.commit()

item19 = Item(
        title='Snowboard',
        description='''Snowboards are boards where both feet are secured to
        the same board, which are wider than skis, with the ability to glide
        on snow.''',
        image='item_images/sport-goods.jpg',
        category=category5,
        user=user1
        )
session.add(item19)
session.commit()

item20 = Item(
        title='Ski Bindings',
        description='''A ski binding is a device that connects a ski boot to
        the ski. Generally, it holds the boot firmly to allow the skier to
        maneuver the ski. However, if certain force limits are exceeded, it
        releases the boot to minimize skier injury, such as in the case of a
        fall or impact.''',
        image='item_images/sport-goods.jpg',
        category=category5,
        user=user1
        )
session.add(item20)
session.commit()

item21 = Item(
        title='Snowboarding Hemlet',
        description='''A ski helmet is a helmet specifically designed and
        constructed for winter sports. Use was rare until about 2000, but by
        about 2010 the great majority of skiers and snowboarders in the US
        and Europe wear helmets.''',
        image='item_images/sport-goods.jpg',
        category=category5,
        user=user1
        )
session.add(item21)
session.commit()

category6 = Category(name='Rock Climbing')
session.add(category6)
session.commit()

item22 = Item(
        title='Rope',
        description='''A rope is a group of yarns, plies, fibers or strands
        that are twisted or braided together into a larger and stronger form.
        Ropes have tensile strength and so can be used for dragging and
        lifting, but are too flexible to provide compressive strength.''',
        image='item_images/sport-goods.jpg',
        category=category6,
        user=user1
        )
session.add(item22)
session.commit()

item23 = Item(
        title='Carabiners',
        description='''A carabiner or karabiner is a specialized type of
        shackle, a metal loop with a spring-loaded gate used to quickly and
        reversibly connect components, most notably in safety-critical
        systems.''',
        image='item_images/sport-goods.jpg',
        category=category6,
        user=user1
        )
session.add(item23)
session.commit()

item24 = Item(
        title='Climbing Harnesses',
        description='''A climbing harness is an item of climbing equipment
        for rock-climbing, abseiling, or other activities requiring the use
        of ropes to provide access or safety such as industrial rope access,
        working at heights, etc. A harness secures a person to a rope or an
        anchor point.''',
        image='item_images/sport-goods.jpg',
        category=category6,
        user=user1
        )
session.add(item24)
session.commit()

category7 = Category(name='Foosball')
session.add(category7)
session.commit()

item25 = Item(
        title='Foosball Table',
        description='''Table football or table soccer, foosball in North
        America, is a table-top game that is loosely based on football. The
        aim of the game is to use the control knobs to move the ball into the
        opponent's goal. There are no unified rules for playing the game, in
        the sense that rules vary in different countries and even in cities,
        and sometimes between different clubs in the same city. ''',
        image='item_images/sport-goods.jpg',
        category=category7,
        user=user1
        )
session.add(item25)
session.commit()

category8 = Category(name='Skating')
session.add(category8)
session.commit()

item26 = Item(
        title='Skates',
        description='''The special boots with the glide blades.''',
        image='item_images/sport-goods.jpg',
        category=category8,
        user=user1
        )
session.add(item26)
session.commit()

item27 = Item(
        title='Soakers',
        description='''Soakers are terry cloth blade covers that protect and
        keep figure skating blades dry. After drying your blades thoroughly,
        soakers should be placed over figure skating blades and then, the
        skates with the soakers on should be placed in the skate bag.''',
        image='item_images/sport-goods.jpg',
        category=category8,
        user=user1
        )
session.add(item27)
session.commit()

item28 = Item(
        title='Guards',
        description='''Every figure skater should have a pair of ice skate
        guards inside his or her skate bag. Blades will be ruined if they
        touch concrete, wood, grass, or any surface besides ice, rubber, or
        carpet, so skate guards are a must. Some skaters wear skate guards
        over their blades as soon as they step off the ice.''',
        image='item_images/sport-goods.jpg',
        category=category8,
        user=user1
        )
session.add(item28)
session.commit()

category9 = Category(name='Hockey')
session.add(category9)
session.commit()

item29 = Item(
        title='Ice hockey stick',
        description='''An ice hockey stick is a piece of equipment used in
        ice hockey to shoot, pass, and carry the puck across the ice. Ice
        hockey sticks are approximately 150-200 cm long, composed of a long,
        slender shaft with a flat extension at one end called the blade.''',
        image='item_images/sport-goods.jpg',
        category=category9,
        user=user1
        )
session.add(item29)
session.commit()

item30 = Item(
        title='Hockey puck',
        description='''A hockey puck is a disk made of vulcanized rubber that
        serves the same functions in various games as ball does in ball games.
        The best-known use of pucks is in ice hockey, a major international
        sport.''',
        image='item_images/sport-goods.jpg',
        category=category9,
        user=user1
        )
session.add(item30)
session.commit()

item31 = Item(
        title='Ice skates',
        description='''Ice skates are boots with blades attached to the bottom,
        used to propel the bearer across a sheet of ice while ice skating. The
        first ice skates were made from leg bones of horse, ox or deer, and
        were attached to feet with leather straps. ''',
        image='item_images/sport-goods.jpg',
        category=category9,
        user=user1
        )
session.add(item31)
session.commit()

print 'categories and items have been added'
